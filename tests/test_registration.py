#!/usr/bin/env python3
"""Test user registration with SQLite backend."""

import socket
import sys
import time


def send_recv(sock, msg):
    """Send message and receive response."""
    sock.sendall((msg + "\n").encode())
    time.sleep(0.2)
    try:
        data = sock.recv(4096).decode()
        return data
    except:
        return ""


def test_registration():
    """Test user registration flow."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        print("[1] Connecting to localhost:42439...")
        sock.connect(("localhost", 42439))

        # Read welcome
        welcome = sock.recv(4096).decode()
        print(f"[2] Server says: {welcome[:100]}")

        # Try to register
        print("[3] Sending: /register testuser testpass123")
        response = send_recv(sock, "/register testuser testpass123")
        print(f"[4] Response: {response}")

        if "successful" in response.lower() or "logged" in response.lower():
            print(" Registration SUCCESS")
            return 0
        else:
            print("❌ Registration FAILED")
            return 1

    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(test_registration())
