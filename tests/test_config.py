import json

import pytest

from scanner.config import ConfigError, ScanConfig, load_config


def test_load_config_from_env(monkeypatch):
    monkeypatch.setenv("EMAIL", "user@yahoo.com")
    monkeypatch.setenv("APP_PASSWORD", "secret")
    monkeypatch.setenv("IMAP_SERVER", "imap.mail.yahoo.com")
    cfg = load_config(env={"EMAIL": "user@yahoo.com", "APP_PASSWORD": "secret", "IMAP_SERVER": "imap.mail.yahoo.com"})
    cfg.validate()
    assert cfg.email == "user@yahoo.com"
    assert cfg.app_password == "secret"


def test_env_overrides_file(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"email": "file@yahoo.com", "app_password": "filepass"}))
    cfg = load_config(config_file, env={"EMAIL": "env@yahoo.com"})
    assert cfg.email == "env@yahoo.com"
    assert cfg.app_password == "filepass"


def test_validate_requires_email():
    cfg = ScanConfig(app_password="x")
    with pytest.raises(ConfigError):
        cfg.validate()


def test_validate_requires_app_password():
    cfg = ScanConfig(email="a@b.com")
    with pytest.raises(ConfigError):
        cfg.validate()


def test_validate_requires_quarantine_folder_nonempty():
    cfg = ScanConfig(email="a@b.com", app_password="x", quarantine_folder="  ")
    with pytest.raises(ConfigError):
        cfg.validate()


def test_virustotal_enabled_requires_api_key():
    cfg = ScanConfig(email="a@b.com", app_password="x", virustotal_enabled=True, vt_api_key="")
    with pytest.raises(ConfigError):
        cfg.validate()


def test_default_dry_run_semantics_no_apply_flag_needed():
    # ScanConfig itself carries no "dry_run" flag: the CLI's --apply is the only
    # thing that can enable mutation. Absence of that flag is the safe default.
    cfg = ScanConfig(email="a@b.com", app_password="x")
    cfg.validate()  # should not raise; nothing here implies mutation


def test_invalid_regex_rejected():
    cfg = ScanConfig(email="a@b.com", app_password="x", regex_rules=["("])
    with pytest.raises(ConfigError):
        cfg.validate()


def test_spoof_identifiers_default_to_own_username():
    cfg = load_config(env={"EMAIL": "john.doe@yahoo.com", "APP_PASSWORD": "x"})
    assert "john.doe" in cfg.spoof_identifiers


def test_config_file_not_found():
    with pytest.raises(ConfigError):
        load_config("/no/such/file.json", env={})
