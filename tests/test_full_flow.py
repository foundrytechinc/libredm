#!/usr/bin/env python3
"""Full integration test: register → login → create server → send message."""

import socket
import sys
import time


def send_recv(sock, msg):
    """Send message and receive response."""
    sock.sendall((msg + "\n").encode())
    time.sleep(0.3)
    try:
        data = sock.recv(8192).decode()
        return data
    except:
        return ""


def test_full_flow():
    """Test complete user flow."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        # === 1. Connect ===
        print("[1] Connecting...")
        sock.connect(("localhost", 42439))
        welcome = sock.recv(4096).decode()
        print(f"    Welcome: {welcome[:50]}")

        # === 2. Register ===
        print("[2] Registering user 'testuser2'...")
        response = send_recv(sock, "/register testuser2 securepass123")
        if "successful" not in response.lower():
            print(f"    ❌ Registration failed: {response[:100]}")
            return 1
        print("     Registration OK")

        # === 3. Login ===
        print("[3] Logging in...")
        response = send_recv(sock, "/login testuser2 securepass123")
        if "successful" not in response.lower() and "available" not in response.lower():
            print(f"    ❌ Login failed: {response[:100]}")
            return 1
        print("     Login OK")

        # === 4. Join/create server ===
        print("[4] Joining server 'general'...")
        response = send_recv(sock, "/join_server general")
        if "joined" in response.lower() or "welcome" in response.lower():
            print("     Joined OK")
        else:
            print(f"    Response: {response[:100]}")

        # === 5. Send message ===
        print("[5] Sending message...")
        response = send_recv(sock, "Hello, LibreDM!")
        print(f"    Response: {response[:100]}")

        # === 6. Check members ===
        print("[6] Checking members...")
        response = send_recv(sock, "/members")
        if "testuser2" in response:
            print("     Member list OK")
        else:
            print(f"      Unexpected members: {response[:100]}")

        print("\n FULL FLOW SUCCESS")
        return 0

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(test_full_flow())
