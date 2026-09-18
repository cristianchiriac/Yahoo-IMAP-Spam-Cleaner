"""Localhost hardening: Host/Origin allow-listing and CSRF token enforcement
for state-changing requests. Localhost is not automatically safe -- a
malicious page open in the same browser could still POST to 127.0.0.1 without
these checks.
"""
from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CSRF_TOKEN = secrets.token_urlsafe(32)


class LocalhostSecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, port: int):
        super().__init__(app)
        self.allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    async def dispatch(self, request: Request, call_next):
        host = (request.headers.get("host") or "").split(":")[0]
        if host not in ALLOWED_HOSTS:
            return JSONResponse({"error": "Host not allowed"}, status_code=400)

        if request.method not in SAFE_METHODS:
            origin = request.headers.get("origin")
            if origin is not None and origin not in self.allowed_origins:
                return JSONResponse({"error": "Origin not allowed"}, status_code=403)

            if request.url.path.startswith("/api/") and request.url.path != "/api/csrf-token":
                token = request.headers.get("x-csrf-token")
                if token != CSRF_TOKEN:
                    return JSONResponse({"error": "Missing or invalid CSRF token"}, status_code=403)

        return await call_next(request)
