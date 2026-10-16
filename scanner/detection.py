"""Explainable, layered spam/phishing/spoofing detection."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr, quote

from .config import ScanConfig, HARD_MATCH_SIGNALS

URL_REGEX = re.compile(r'https?://[^\s<>"\'{}|\\^`]+')


@dataclass
class Signal:
    name: str
    weight: int
    detail: str
    hard_match: bool = False

    def to_dict(self) -> dict:
        return {"name": self.name, "weight": self.weight, "detail": self.detail, "hard_match": self.hard_match}


@dataclass
class Finding:
    uid: str
    subject: str
    sender: str
    score: int
    verdict: str  # "spam" | "clean" | "incomplete"
    matched_hard_rule: str | None
    signals: list[Signal] = field(default_factory=list)
    folder: str = ""

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "subject": self.subject,
            "sender": self.sender,
            "score": self.score,
            "verdict": self.verdict,
            "matched_hard_rule": self.matched_hard_rule,
            "signals": [s.to_dict() for s in self.signals],
            "folder": self.folder,
        }


def normalize_text(text: str) -> str:
    if not text:
        return ""
    without_diacritics = "".join(
        c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn"
    )
    return re.sub(r"\s+", " ", without_diacritics)


def decode_header_value(value) -> str:
    """Decodes RFC 2047 encoded-words ('=?UTF-8?B?...?=') and unfolds the
    header. Messages parsed with the default compat32 policy keep headers
    encoded, so without this every keyword/brand check silently misses any
    subject or display name with non-ASCII text. Malformed encodings fall
    back to the raw text instead of failing the message."""
    if value is None:
        return ""
    text = str(value)
    try:
        text = str(make_header(decode_header(text)))
    except Exception:  # noqa: BLE001 - hostile/malformed headers must not abort a scan
        pass
    lines = text.splitlines()
    if len(lines) <= 1:
        return text
    return " ".join([lines[0].rstrip()] + [line.strip() for line in lines[1:]])


def normalize_from_header(raw_from) -> str:
    """Returns the From header with its display name decoded, as
    '"Name" <address>'. The address is taken from the RAW header and only the
    display name is decoded: a name that decodes to 'PayPal
    <service@paypal.com>' must never be able to replace the real address."""
    raw_text = "" if raw_from is None else str(raw_from)
    name, addr = parseaddr(raw_text)
    if not addr:
        return decode_header_value(raw_text)
    name = decode_header_value(name).strip()
    if not name:
        return addr
    return f'"{quote(name)}" <{addr}>'


def _domain_of(email_addr: str) -> str:
    email_addr = email_addr.lower()
    return email_addr.split("@")[1] if "@" in email_addr else ""


def _matches_domain_set(domain: str, domain_set: set[str]) -> str | None:
    for candidate in domain_set:
        candidate = candidate.lower()
        if domain == candidate or domain.endswith("." + candidate):
            return candidate
    return None


def _domains_related(a: str, b: str) -> bool:
    """True if a and b are the same domain, or one is a subdomain of the
    other (e.g. bounce.email.example.com is related to example.com). Bulk
    mail providers routinely send from/bounce-through subdomains of the same
    brand -- that is not a mismatch and must not be treated as one."""
    if not a or not b:
        return False
    a, b = a.lower(), b.lower()
    return a == b or a.endswith("." + b) or b.endswith("." + a)


_GIBBERISH_LOCALPART_RE = re.compile(r"^(?:[A-Z][a-z]{2,}){3,}$")


def _looks_like_gibberish_localpart(local_part: str) -> bool:
    """Heuristic for auto-generated local-parts made of several concatenated
    capitalized words with no separators, e.g. 'XenolithsHideInGnaniteSlabs'
    or 'ThermalConductivityGasDetectorWheatstoneBridge'. Real human mailbox
    names essentially never look like this."""
    return len(local_part) >= 18 and bool(_GIBBERISH_LOCALPART_RE.match(local_part))


def check_spoofed_sender(from_header: str, spoof_identifiers: list[str], own_email: str) -> Signal | None:
    real_name, actual_email = parseaddr(from_header)
    actual_email_l = actual_email.lower()
    for identifier in spoof_identifiers:
        identifier_l = identifier.lower()
        if identifier_l and (identifier_l in real_name.lower() or identifier_l in actual_email_l):
            if actual_email_l != own_email.lower():
                return Signal(
                    "spoofed_sender", 0,
                    f"Display name/address impersonates '{identifier}' but actually comes from {actual_email}",
                    hard_match=True,
                )
    return None


def check_blocked_domain(from_header: str, blocked_domains: set[str]) -> Signal | None:
    _, actual_email = parseaddr(from_header)
    domain = _domain_of(actual_email)
    if not domain:
        return None
    hit = _matches_domain_set(domain, blocked_domains)
    if hit:
        return Signal("blocked_domain", 0, f"Sender domain '{domain}' is on the blocked list", hard_match=True)
    return None


def check_blocked_sender(from_header: str, blocked_senders: set[str]) -> Signal | None:
    _, actual_email = parseaddr(from_header)
    actual_email = actual_email.lower()
    if actual_email and actual_email in blocked_senders:
        return Signal("blocked_sender", 0, f"Sender address '{actual_email}' is on the blocked list", hard_match=True)
    return None


def _extract_header_domain(raw_value: str | None) -> str:
    """Domain from a header that should hold an address, tolerating malformed
    values like 'Reply-To: mmiandassociates.com' (no @, no angle brackets) that
    parseaddr cannot resolve to an address."""
    if not raw_value:
        return ""
    _, addr = parseaddr(raw_value)
    domain = _domain_of(addr)
    if domain:
        return domain
    # No '@' found by parseaddr -- the raw value may itself just be a bare
    # domain (a common malformed-Reply-To pattern in bulk spam).
    candidate = raw_value.strip().strip("<>").lower()
    if candidate and "@" not in candidate and "." in candidate and " " not in candidate:
        return candidate
    return ""


def check_reply_to_return_path(msg: Message, from_header: str) -> list[Signal]:
    signals = []
    _, from_addr = parseaddr(from_header)
    from_domain = _domain_of(from_addr)

    reply_domain = _extract_header_domain(msg.get("Reply-To"))
    if reply_domain and from_domain and not _domains_related(reply_domain, from_domain):
        signals.append(Signal(
            "reply_to_mismatch", 0,
            f"Reply-To domain '{reply_domain}' is unrelated to From domain '{from_domain}'",
        ))

    rp_domain = _extract_header_domain(msg.get("Return-Path"))
    if rp_domain and from_domain and not _domains_related(rp_domain, from_domain):
        signals.append(Signal(
            "return_path_mismatch", 0,
            f"Return-Path domain '{rp_domain}' is unrelated to From domain '{from_domain}'",
        ))
    return signals


def check_brand_impersonation(msg: Message, from_header: str, protected_brand_domains: set[str]) -> Signal | None:
    """Flags a message whose Reply-To or Return-Path claims a well-known,
    protected brand domain (e.g. amazon.com) while the actual From domain is
    unrelated to it -- a common scam pattern where the bounce/reply address is
    set to a trusted-looking domain to survive a casual glance, even though
    that domain never actually sent the message."""
    if not protected_brand_domains:
        return None
    _, from_addr = parseaddr(from_header)
    from_domain = _domain_of(from_addr)

    for header_name in ("Return-Path", "Reply-To"):
        claimed_domain = _extract_header_domain(msg.get(header_name))
        if not claimed_domain:
            continue
        hit = _matches_domain_set(claimed_domain, protected_brand_domains)
        if hit and not _domains_related(claimed_domain, from_domain):
            return Signal(
                "brand_impersonation", 0,
                f"{header_name} claims protected brand domain '{hit}' but the message actually "
                f"comes from an unrelated domain '{from_domain}'",
                hard_match=True,
            )
    return None


def check_brand_name_mismatch(
    from_header: str, subject: str, protected_brand_domains: set[str],
) -> Signal | None:
    """2026-era phishing increasingly rents entirely legitimate ESP
    infrastructure (own domain, valid SPF/DKIM/DMARC) and never forges a
    single header -- it just names a trusted brand in the display name or
    subject ('AspireRewards', 'Your Auto Quote Team', fake Amazon-style
    offers) while sending from an unrelated domain. Header-based checks can't
    catch that, so this looks at the brand's own name appearing in the
    From display name or Subject while the sending domain is unrelated to
    that brand's real domain. Scored, not a hard match, since legitimate
    resellers/affiliates can mention a brand by name."""
    real_name, actual_email = parseaddr(from_header)
    sender_domain = _domain_of(actual_email)
    haystack = f"{real_name} {subject}".lower()

    ambiguous_common_words = {"chase", "apple"}  # too likely to false-positive as ordinary words
    for brand_domain in protected_brand_domains:
        brand_name = brand_domain.split(".")[0].lower()
        if len(brand_name) < 5 or brand_name in ambiguous_common_words:
            continue
        if re.search(r"\b" + re.escape(brand_name) + r"\b", haystack) and not _domains_related(sender_domain, brand_domain):
            return Signal(
                "brand_name_mismatch", 0,
                f"Mentions brand '{brand_name}' in sender name/subject but sends from "
                f"unrelated domain '{sender_domain}'",
            )
    return None


def check_subject_obfuscation(subject: str) -> Signal | None:
    """Detects irregular/excessive whitespace used to dodge keyword filters,
    e.g. 'Drive      &       Save            Up   To   50%'."""
    if not subject:
        return None
    gaps = re.findall(r" {2,}", subject)
    if len(gaps) >= 3:
        return Signal(
            "subject_obfuscation", 0,
            f"Subject contains {len(gaps)} irregular multi-space gaps, a common filter-evasion pattern",
        )
    return None


def check_gibberish_localpart(from_header: str) -> Signal | None:
    """Detects sender local-parts made of several concatenated capitalized
    words with no separators (e.g. 'XenolithsHideInGnaniteSlabs@...'), typical
    of auto-generated bulk-spam mailbox names."""
    _, actual_email = parseaddr(from_header)
    local_part = actual_email.split("@")[0] if "@" in actual_email else ""
    if _looks_like_gibberish_localpart(local_part):
        return Signal(
            "gibberish_localpart", 0,
            f"Sender local-part '{local_part}' looks auto-generated, not a real mailbox name",
        )
    return None


def check_email_auth(msg: Message) -> Signal | None:
    """Checks both Authentication-Results ('spf=fail ...') and the older
    Received-SPF header, whose value conventionally starts with the bare
    result word (e.g. 'fail (domain of ... does not designate ...)') rather
    than an 'spf: fail' label -- match that shape too, not just the labeled
    one, or real-world SPF failures on that header are silently missed."""
    auth_header = str(msg.get("Authentication-Results", "")).lower()
    spf_header = str(msg.get("Received-SPF", "")).lower().strip()

    def spf_result_is(word: str) -> bool:
        return f"spf={word}" in auth_header or f"spf: {word}" in spf_header or spf_header.startswith(word)

    if "dmarc=fail" in auth_header or spf_result_is("fail"):
        return Signal("auth_hard_fail", 0, "SPF/DMARC hard fail")
    if spf_result_is("softfail"):
        return Signal("auth_soft_fail", 0, "SPF softfail")
    if spf_result_is("none"):
        return Signal("auth_missing", 0, "No SPF record found")
    return None


def _decode_part(part: Message) -> str:
    """Decodes a part's payload using its declared charset (e.g. iso-8859-2,
    windows-1250), falling back to UTF-8 for a missing or unknown one."""
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="ignore")
    except LookupError:
        return payload.decode("utf-8", errors="ignore")


def get_email_body(msg: Message) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                body += _decode_part(part)
    else:
        body = _decode_part(msg)
    return body


def analyze_urls(
    body_text: str, blocked_domains: set[str], safe_domains: set[str], sender_domain: str = "",
) -> tuple[Signal | None, list[str]]:
    """Flags URLs to blocked/unrecognized domains. A link to the sender's own
    domain (or a subdomain of it) is normal marketing/tracking behavior, not
    suspicious, and is excluded -- otherwise nearly every legitimate bulk
    email (which always links back to its own site) gets flagged."""
    urls = URL_REGEX.findall(body_text)
    suspicious = []
    distinct_domains: set[str] = set()
    for url in urls:
        domain_match = re.search(r'https?://(?:www\.)?([^/:\?]+)', url.lower())
        if not domain_match:
            continue
        domain = domain_match.group(1)
        if _matches_domain_set(domain, blocked_domains):
            return Signal("blocked_url", 0, f"URL points to blocked domain '{domain}'", hard_match=True), []
        if _matches_domain_set(domain, safe_domains):
            continue
        if sender_domain and _domains_related(domain, sender_domain):
            continue
        suspicious.append(url)
        distinct_domains.add(domain)
    signal = None
    if suspicious:
        signal = Signal(
            "suspicious_url", 0,
            f"{len(suspicious)} URL(s) to {len(distinct_domains)} domain(s) unrelated to sender and not on any trusted list",
        )
    return signal, suspicious


def evaluate_message(
    msg: Message,
    uid: str,
    cfg: ScanConfig,
    vt_lookup=None,
) -> Finding:
    """Evaluate a single message and produce an explainable Finding.

    `vt_lookup(url) -> Signal | "incomplete" | None` is an optional callable
    used only when VirusTotal is enabled; it must never be invoked otherwise.
    """
    from .config import DEFAULT_SCORE_WEIGHTS  # local import to avoid cycle at module load

    weights = cfg.score_weights or DEFAULT_SCORE_WEIGHTS
    from_header = normalize_from_header(msg.get("From", ""))
    subject = decode_header_value(msg.get("Subject", ""))
    signals: list[Signal] = []
    incomplete = False

    def add(sig: Signal | None):
        if sig is None:
            return
        sig.weight = weights.get(sig.name, 0)
        signals.append(sig)

    add(check_spoofed_sender(from_header, cfg.spoof_identifiers, cfg.email))
    add(check_blocked_domain(from_header, cfg.blocked_domains))
    add(check_blocked_sender(from_header, cfg.blocked_senders))
    add(check_brand_impersonation(msg, from_header, cfg.protected_brand_domains))
    add(check_gibberish_localpart(from_header))
    add(check_brand_name_mismatch(from_header, subject, cfg.protected_brand_domains))
    for s in check_reply_to_return_path(msg, from_header):
        add(s)
    add(check_email_auth(msg))

    subject_norm = normalize_text(subject).strip()
    if not subject_norm:
        add(Signal("empty_subject", 0, "Subject is empty"))
    add(check_subject_obfuscation(subject))

    keyword_re = cfg.compiled_keywords()
    if keyword_re and keyword_re.search(subject_norm):
        add(Signal("keyword_subject", 0, "Spam keyword found in subject"))

    body = get_email_body(msg)
    body_norm = normalize_text(body)
    if keyword_re and keyword_re.search(body_norm):
        add(Signal("keyword_body", 0, "Spam keyword found in body"))

    for pattern in cfg.compiled_regex_rules():
        if pattern.search(subject_norm) or pattern.search(body_norm):
            add(Signal("regex_rule", 0, f"Matched custom regex rule: {pattern.pattern}"))
            break

    _, sender_addr = parseaddr(from_header)
    sender_domain = _domain_of(sender_addr)
    url_signal, suspicious_urls = analyze_urls(body, cfg.blocked_domains, cfg.safe_domains, sender_domain)
    add(url_signal)

    if cfg.virustotal_enabled and vt_lookup and suspicious_urls:
        result = vt_lookup(suspicious_urls[0])
        if result == "incomplete":
            incomplete = True
        elif isinstance(result, Signal):
            add(result)

    total_score = sum(s.weight for s in signals if not s.hard_match)
    hard_hits = [s for s in signals if s.hard_match]

    if hard_hits:
        verdict = "spam"
        matched_hard_rule = hard_hits[0].name
        total_score = max(total_score, 100)
    elif incomplete and total_score < cfg.score_threshold:
        verdict = "incomplete"
        matched_hard_rule = None
    elif total_score >= cfg.score_threshold:
        verdict = "spam"
        matched_hard_rule = None
    else:
        verdict = "clean"
        matched_hard_rule = None

    return Finding(
        uid=uid,
        subject=subject,
        sender=from_header,
        score=total_score,
        verdict=verdict,
        matched_hard_rule=matched_hard_rule,
        signals=signals,
    )
