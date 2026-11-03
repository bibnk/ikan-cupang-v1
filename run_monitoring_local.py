#!/usr/bin/env python3
"""
Local Runner for VPS Monitoring Dashboard on port 4092.
Supports root access, auto-redirect, and multi-threading.
"""

import os
import sys

# Ensure repository root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from werkzeug.serving import run_simple
from flask import redirect
from wsgi import application, public_app, MOUNT


@public_app.route("/")
def public_root_redirect():
    return redirect(f"{MOUNT}/monitoring")


@public_app.route("/monitoring")
def public_monitoring_redirect():
    return redirect(f"{MOUNT}/monitoring")


@public_app.route("/login")
def public_login_redirect():
    return redirect(f"{MOUNT}/login")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 4092))
    print("=" * 65)
    print(f" 🌐 VPS MONITORING HUB (LOCAL RUNNER)")
    print("=" * 65)
    print(f"[*] Port           : {port}")
    print(f"[*] Local URL      : http://localhost:{port}/")
    print(f"[*] Monitoring URL : http://localhost:{port}{MOUNT}/monitoring")
    print(f"[*] Kode Login     : monitor (atau sbb)")
    print("=" * 65)
    run_simple("0.0.0.0", port, application, use_reloader=False, threaded=True)
