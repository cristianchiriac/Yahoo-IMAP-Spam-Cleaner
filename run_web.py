#!/usr/bin/env python3
"""Start the local Yahoo IMAP Scanner web app.

Binds to 127.0.0.1 only, never 0.0.0.0. No cloud services, no telemetry.
"""
from __future__ import annotations

import uvicorn

from web.app import app, configure_security

HOST = "127.0.0.1"
PORT = 8765

if __name__ == "__main__":
    configure_security(PORT)
    print(f"Yahoo IMAP Scanner running at http://{HOST}:{PORT} (local only)")
    uvicorn.run(app, host=HOST, port=PORT)
