"""Client connection handling: login, command loop, cleanup."""

import json
import socket
import time

from dmcd import config
from dmcd import crypto
from dmcd.commands import (
    CommandContext,
    handle_command,
    handle_chat_message,
    is_ping,
    is_at_command,
)
from dmcd.sessions import Session, send_to_client
from dmcd.textstream import TextStream
from dmcd.s2s import log_message
from dmcd.sanitize import (
    is_reserved_username,
    sanitize_text,
    sanitize_username,
)


def sanitize_command(command: str) -> str:
    """Mask passwords and strip control chars for safe log output."""
    from dmcd.sanitize import strip_controls
    parts = command.split(None, 2)
    if len(parts) >= 3 and parts[0] in ("/login", "/register"):
        # /login username password → /login username [REDACTED]
        command = f"{parts[0]} {parts[1]} [REDACTED]"
    # Neutralize CR/LF so a crafted command cannot forge log lines.
    return strip_controls(command)[:512]


def _is_encrypted_connection(client_socket, client_key) -> bool:
    if client_key is not None:
        return True
    try:
        import ssl
        return isinstance(client_socket, ssl.SSLSocket)
    except Exception:
        return False



S2S_INBOUND_TYPES = frozenset({
    "s2s_cap", "remote_pm", "dialback_check", "s2s_ping", "status_request",
    "presence_subscribe", "presence_unsubscribe", "presence_update",
    "room_join", "room_leave", "room_message", "room_act",
    "room_members_request", "room_event",
})


def receive_from_client(client_socket, client_key=None, text_in=None):
    try:
        if client_key:
            if isinstance(client_key, tuple):
                enc_key, mac_key = client_key
            else:
                enc_key, mac_key = client_key, None
            line = crypto.receive_encrypted(client_socket, enc_key, mac_key)
            if isinstance(line, str) and len(line) > config.MAX_MESSAGE_LENGTH + 128:
                return line[: config.MAX_MESSAGE_LENGTH + 128]
            return line
        if text_in is None:
            text_in = TextStream()
        while True:
            line = text_in.read(client_socket)
            if line is None:
                return None
            if line == "":
                return ""
            if is_at_command(line):
                text_in.mark_telnet()
                continue
            return line
    except Exception as e:
        log_message(f"Error receiving from client: {e}")
        return None


def handle_client(client_socket, client_address, a, client_key=None):
    session = Session(client_socket, client_address)
    session.client_key = client_key
    text_in = None
    use_encryption = client_key is not None

    if not use_encryption:
        text_in = TextStream()
    session.text_in = text_in
    a.sessions.register(session)

    log_message(
        f"TCP client {client_address} connected "
        f"{'(encrypted)' if use_encryption else '(unencrypted)'}."
    )

    if not use_encryption and text_in:
        try:
            client_socket.settimeout(config.PEEK_TIMEOUT)
            peek = client_socket.recv(config.MAX_PACKET_SIZE, socket.MSG_PEEK)
            if peek:
                if config.CTRL_ESC in peek:
                    text_in.mark_telnet()
                elif TextStream.looks_like_plain_line_protocol(peek) or (
                    peek in (b"/", b"//") or TextStream.looks_like_tcp_batch(peek)
                ):
                    text_in.mode = "plain"
                    text_in.encoding = "utf-8"
                    text_in.plain_candidate = False
            client_socket.settimeout(None)
        except Exception:
            try:
                client_socket.settimeout(None)
            except Exception:
                pass

    logged_in = False
    try:
        stashed_command = None
        if not use_encryption and text_in:
            stashed_command = _drain_stashed(client_socket, text_in)

        send_to_client(client_socket, "Enter command (/login /register): ", client_key)

        while not logged_in:
            command = (
                stashed_command
                if stashed_command is not None
                else receive_from_client(client_socket, client_key, text_in)
            )
            stashed_command = None

            if command is None or command == "":
                break

            if is_ping(command):
                send_to_client(client_socket, "*Ping!*", client_key)
                continue

            log_message(f"TCP {client_address} message: {sanitize_command(command)}")
            client_ip = client_address[0] if isinstance(client_address, tuple) else str(client_address)

            if command.startswith("/register"):
                _do_register(command, client_socket, client_key, a, client_ip)
                send_to_client(client_socket, "Enter command (/login /register): ", client_key)
                continue

            if command.startswith("/login"):
                username = _do_login(command, client_socket, client_key, a, client_ip, session)
                if username:
                    logged_in = True
                    break
                send_to_client(client_socket, "Enter command (/login /register): ", client_key)
                continue

            send_to_client(client_socket, "Unknown command.", client_key)
            send_to_client(client_socket, "Enter command (/login /register): ", client_key)

        if logged_in:
            _command_loop(client_socket, client_address, a, client_key, text_in, session)

    except (ConnectionResetError, BrokenPipeError):
        log_message(f"TCP client {client_address} disconnected unexpectedly.")
    except Exception as e:
        log_message(f"TCP client {client_address} error: {e}")
    finally:
        _cleanup(a, session, client_address)


def _recv_json_line(client_socket) -> dict:
    """Read one newline-terminated JSON object (bounded)."""
    buf = b""
    while len(buf) < config.MAX_PACKET_SIZE and b"\n" not in buf:
        chunk = client_socket.recv(min(4096, config.MAX_PACKET_SIZE - len(buf)))
        if not chunk:
            break
        buf += chunk
    line = buf.split(b"\n", 1)[0].strip()
    if not line:
        raise ValueError("empty s2s line")
    msg = json.loads(line.decode("utf-8"))
    if not isinstance(msg, dict):
        raise ValueError("s2s message must be an object")
    return msg


def try_plain_s2s(client_socket, client_address, a, peek: bytes) -> bool:
    """Handle a plain JSON S2S message. Returns True if the socket was consumed."""
    if not peek:
        return False
    # Peek is only a sniff: decide whether this *might* be plain S2S. The
    # message that is actually processed must be re-read and re-validated —
    # never trust the peeked bytes as the payload (TOCTOU).
    try:
        probed = json.loads(peek.decode("utf-8").strip())
    except Exception:
        return False
    if not (isinstance(probed, dict) and probed.get("type") in S2S_INBOUND_TYPES):
        return False

    try:
        msg = _recv_json_line(client_socket)
    except Exception:
        return True

    if msg.get("type") not in S2S_INBOUND_TYPES:
        try:
            client_socket.send(
                (json.dumps({"status": "error", "reason": "bad_request"}, ensure_ascii=False) + "\n").encode("utf-8")
            )
        except Exception:
            pass
        return True
    # Cleartext S2S is only kept for capability discovery when encryption
    # is mandatory — all other types must arrive on the encrypted transport.
    if config.S2S_REQUIRE_ENCRYPTED and msg.get("type") != "s2s_cap":
        try:
            client_socket.send(
                (json.dumps({"status": "error", "reason": "encryption_required"}, ensure_ascii=False) + "\n").encode("utf-8")
            )
        except Exception:
            pass
        return True

    def _plain_reply(payload):
        try:
            client_socket.send(
                (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
            )
        except Exception:
            pass

    from dmcd.s2s_handler import process_s2s_message
    process_s2s_message(msg, _plain_reply, client_socket, client_address, a)
    return True


def _drain_stashed(client_socket, text_in):
    try:
        client_socket.settimeout(config.DRAIN_TIMEOUT)
        drain_end = time.time() + 2.0
        while time.time() < drain_end:
            try:
                line = text_in.read(client_socket)
            except Exception:
                break
            if line is None:
                break
            if line == "":
                continue
            if is_at_command(line):
                text_in.mark_telnet()
                continue
            return line
    finally:
        try:
            client_socket.settimeout(None)
        except Exception:
            pass
    return None


def _do_register(command, client_socket, client_key, a, client_ip) -> bool:
    if config.REQUIRE_ENCRYPTED_AUTH and not _is_encrypted_connection(client_socket, client_key):
        send_to_client(
            client_socket,
            "Registration requires an encrypted connection (TLS or the encrypted port). "
            "Official DMConnect clients: set REQUIRE_ENCRYPTED_AUTH = False in dmcd/config.py.",
            client_key,
        )
        return False
    if not a.register_limiter.allow(client_ip):
        send_to_client(client_socket, "Too many attempts. Try again later.", client_key)
        return False
    parts = command.split(" ", 2)
    if len(parts) != 3:
        send_to_client(client_socket, "Usage: /register <username> <password>", client_key)
        return False
    _, username, password = parts
    username = sanitize_username(username)
    if not username:
        send_to_client(client_socket, "Invalid username.", client_key)
        return False
    if is_reserved_username(username):
        send_to_client(client_socket, "Username is reserved.", client_key)
        return False
    if len(password) < 8 or len(password) > config.MAX_PASSWORD_LENGTH:
        send_to_client(
            client_socket,
            f"Password must be 8-{config.MAX_PASSWORD_LENGTH} characters.",
            client_key,
        )
        return False
    if a.users.register(username, password):
        send_to_client(client_socket, "Registration successful. Please log in.", client_key)
        return True
    send_to_client(client_socket, "Username already taken. Try another.", client_key)
    return False


def _do_login(command, client_socket, client_key, a, client_ip, session):
    if config.REQUIRE_ENCRYPTED_AUTH and not _is_encrypted_connection(client_socket, client_key):
        send_to_client(
            client_socket,
            "Login requires an encrypted connection (TLS or the encrypted port). "
            "Official DMConnect clients: set REQUIRE_ENCRYPTED_AUTH = False in dmcd/config.py.",
            client_key,
        )
        return None
    if not a.login_limiter.allow(client_ip):
        send_to_client(client_socket, "Too many attempts. Try again later.", client_key)
        return None
    parts = command.split(" ", 2)
    if len(parts) != 3:
        send_to_client(client_socket, "Usage: /login <username> <password>", client_key)
        return None
    _, username_raw, password = parts
    username = sanitize_username(username_raw)
    if not username:
        # Legacy compatibility: accounts imported from old DMCD (users.json)
        # may contain chars outside the strict set. Accept the input only if
        # it exactly matches an existing account (after control-char strip) —
        # otherwise reject. Never create/lookup free-form names.
        from dmcd.sanitize import strip_controls
        legacy = strip_controls(username_raw).strip()
        if legacy and len(legacy) <= config.MAX_USERNAME_LENGTH and a.users.exists(legacy):
            username = legacy
    if not username:
        send_to_client(client_socket, "Invalid username or password.", client_key)
        return None
    if len(password) > config.MAX_PASSWORD_LENGTH:
        send_to_client(client_socket, "Invalid username or password.", client_key)
        return None
    locked_for = a.login_lockout.is_locked(username)
    if locked_for:
        send_to_client(
            client_socket,
            f"Account temporarily locked. Try again in {int(locked_for) + 1}s.",
            client_key,
        )
        return None
    stored = a.users.get_hash(username)
    if stored is None or not crypto.verify_password(password, stored):
        left = a.login_lockout.record_failure(username)
        if left:
            send_to_client(
                client_socket,
                f"Invalid username or password. Account locked for {int(left) + 1}s.",
                client_key,
            )
        else:
            send_to_client(client_socket, "Invalid username or password.", client_key)
        return None

    a.login_lockout.clear(username)

    # Upgrade legacy hashes transparently on successful login.
    if crypto.needs_rehash(stored):
        a.users.set_hash(username, crypto.hash_password(password))

    if a.bans.is_banned(username):
        send_to_client(client_socket, "You are banned.", client_key)
        return None

    was_offline = not a.sessions.is_user_online(username)
    a.sessions.set_username(session, username)
    send_to_client(client_socket, "Login successful.", client_key)
    send_to_client(
        client_socket,
        f"Available servers: {', '.join(a.rooms_store.names())}",
        client_key,
    )
    send_to_client(
        client_socket,
        "Select a server using /join_server <server_name>.",
        client_key,
    )
    if was_offline:
        try:
            from caps import status as status_cap
            status_cap.notify_status_change(username, True)
        except Exception:
            pass
    return username


def _command_loop(client_socket, client_address, a, client_key, text_in, session):
    while True:
        message = receive_from_client(client_socket, client_key, text_in)
        if message is None or message == "":
            break

        if is_ping(message):
            send_to_client(client_socket, "*Ping!*", client_key)
            continue

        log_message(f"TCP {client_address} message: {sanitize_command(message)}")
        ctx = CommandContext(a, session, client_key)

        if message.startswith("/"):
            try:
                handle_command(message, ctx)
            except Exception as e:
                log_message(f"command error: {e}")
                send_to_client(client_socket, "Internal error.", client_key)
        else:
            handle_chat_message(message, ctx)


def _cleanup(a, session, client_address):
    try:
        last = a.sessions.unregister(session)
        if last and session.username:
            try:
                from caps import status as status_cap
                status_cap.notify_status_change(session.username, False)
            except Exception:
                pass

        if session.server_name:
            from dmcd.rooms import parse_room_and_host
            room_name, host_part = parse_room_and_host(session.server_name)
            if host_part is None:
                was_last = a.rooms.remove_member(room_name, session.username, config.MY_SERVER_HOST)
                if was_last:
                    a.rooms_store.remove_member(room_name, session.username)
                    text = f"*** {session.username} has left the server."
                    from dmcd.rooms import broadcast_message
                    broadcast_message(
                        text, session.server_name,
                        sender=session.username,
                        filter_fn=a.should_filter_message,
                    )
                    try:
                        from dmcd.commands import _send_room_event_to_remotes
                        a.task_pool.submit_thread(
                            _send_room_event_to_remotes,
                            a, room_name, "left", session.username, config.MY_SERVER_HOST, None,
                        )
                    except Exception:
                        pass
            else:
                key = (session.username, room_name, host_part)
                if a.rooms.remote_counter_dec(key):
                    try:
                        a.s2s.send_json(host_part, {
                            "type": "room_leave",
                            "room": room_name,
                            "sender": session.username,
                            "from_host": config.MY_SERVER_HOST,
                            "msg_id": f"leave:{session.username}:{room_name}:{time.time_ns()}",
                        }, wait_response=False)
                    except Exception:
                        pass
    except Exception as e:
        log_message(f"cleanup error: {e}")
    finally:
        try:
            session.client_socket.close()
        except Exception:
            pass
        a.sessions.shutdown_socket(session.client_socket)
        log_message(f"TCP client {client_address} disconnected.")
