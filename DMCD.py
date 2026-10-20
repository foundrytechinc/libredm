#!/usr/bin/env python3
"""LibreDM — free Apache-2.0 server for the decentralized DM protocol.

Edit dmcd/config.py first (MY_SERVER_HOST, ADMIN_USERNAME), then:

    python3 DMCD.py
"""

import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from Crypto.Cipher import AES  # noqa: F401
except ImportError:
    try:
        from Cryptodome.Cipher import AES  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "You need to install pycryptodome: pip install pycryptodome\n"
        )
        sys.exit(1)

from dmcd.app import app
from dmcd.server import start_tcp_server, start_key_exchange_server, cleanup_tasks
from dmcd.sessions import send_to_client
from dmcd.client import handle_client, receive_from_client  # noqa: F401 (compat)


def _load_capabilities():
    from caps.caps import CapabilitiesManager
    app.capabilities_manager = CapabilitiesManager()
    try:
        from caps import status as status_cap
        status_cap.bind_app(app)
    except Exception:
        pass


def main():
    _load_capabilities()
    threading.Thread(target=cleanup_tasks, args=(app,), daemon=True).start()
    threading.Thread(target=start_key_exchange_server, args=(app,), daemon=True).start()
    threading.Thread(target=start_tcp_server, args=(app,), daemon=True).start()
    # Keep the main thread alive.
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
