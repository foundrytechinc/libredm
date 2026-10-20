"""TCP listeners, connection dispatch, background maintenance."""

import socket
import ssl
import threading
import time

from dmcd import config
from dmcd import crypto
from dmcd.client import handle_client, S2S_INBOUND_TYPES
from dmcd.s2s import log_message


def _maybe_wrap_tls(server_socket):
    if not config.TLS_CERTFILE or not config.TLS_KEYFILE:
        return server_socket
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(config.TLS_CERTFILE, config.TLS_KEYFILE)
    return ctx.wrap_socket(server_socket, server_side=True)


def _build_listener(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(config.LISTEN_BACKLOG)
    return server_socket


def start_key_exchange_server(a, host="0.0.0.0", port=None):
    port = port or config.ENCRYPTED_PORT
    server_socket = _build_listener(host, port)
    log_message(f"TCP encrypted server started on {host}:{port}")

    while True:
        try:
            client_socket, client_address = server_socket.accept()
        except Exception as e:
            log_message(f"accept error (encrypted): {e}")
            continue
        if not a.acquire_connection():
            try:
                client_socket.close()
            except Exception:
                pass
            continue
        threading.Thread(
            target=_handle_encrypted_client,
            args=(client_socket, client_address, a),
            daemon=True,
        ).start()


def _handle_encrypted_client(client_socket, client_address, a):
    try:
        try:
            client_socket.settimeout(2.0)
            peek = b""
            try:
                peek = client_socket.recv(1024, socket.MSG_PEEK)
            except Exception:
                peek = b""
            finally:
                try:
                    client_socket.settimeout(None)
                except Exception:
                    pass

            # Text / Telnet client accidentally on the encrypted port:
            # fall back to the plain protocol instead of failing DH.
            if peek and _looks_like_text_client(peek):
                log_message(
                    f"{client_address}: text client on encrypted port, falling back to plain."
                )
                handle_client(client_socket, client_address, a, client_key=None)
                return

            client_first = bool(peek) and not _looks_like_text_client(peek)
            if client_first:
                # Peer already sent its DH public value.
                b_bytes = crypto.dh_recv_public(client_socket)
                ctx = crypto.DHContext()
                crypto.dh_send_public(client_socket, ctx.public_bytes())
                keys = crypto.derive_session_keys(ctx.shared_secret(b_bytes))
            else:
                keys = crypto.dh_server(client_socket)
            enc_key, mac_key = keys
        except Exception as e:
            log_message(f"Key exchange error for {client_address}: {e}")
            return
        handle_client(client_socket, client_address, a, client_key=(enc_key, mac_key))
    finally:
        a.release_connection()
        try:
            client_socket.close()
        except Exception:
            pass


def _looks_like_text_client(peek: bytes) -> bool:
    if not peek:
        return False
    # Telnet IAC
    if peek[0] == 255:
        return True
    # Plain line protocol / commands
    if peek[:1] in (b"/", b"{"):
        return True
    if b"\n" in peek[:64] or b"\r" in peek[:64]:
        return True
    # ASCII-ish text (not a binary DH length prefix)
    if all(32 <= b < 127 or b in (9, 10, 13) for b in peek[:8]):
        return True
    return False


def start_tcp_server(a, host="0.0.0.0", port=None):
    port = port or config.TCP_PORT
    server_socket = _build_listener(host, port)
    log_message(f"TCP server started on {host}:{port}")

    while True:
        try:
            client_socket, client_address = server_socket.accept()
        except Exception as e:
            log_message(f"accept error: {e}")
            continue
        if not a.acquire_connection():
            try:
                client_socket.close()
            except Exception:
                pass
            continue
        threading.Thread(
            target=_dispatch_connection,
            args=(client_socket, client_address, a),
            daemon=True,
        ).start()


def _dispatch_connection(sock, addr, a):
    handled = False
    try:
        sock.settimeout(0.5)
        try:
            peek = sock.recv(1024, socket.MSG_PEEK)
        except socket.timeout:
            peek = b""
        except Exception:
            peek = b""
        finally:
            try:
                sock.settimeout(None)
            except Exception:
                pass

        # Raw capability handlers (e.g. HTTP file upload).
        if a.capabilities_manager is not None:
            try:
                if a.capabilities_manager.try_handle_raw_connection(sock, addr, peek):
                    handled = True
                    return
            except Exception:
                pass

        # Encrypted S2S.
        if peek.startswith(config.S2S_MAGIC):
            a.s2s.handle_inbound(sock, lambda msg, reply, s: _s2s_encrypted(msg, reply, s, addr, a))
            handled = True
            return

        # Plain JSON S2S.
        try:
            from dmcd.client import try_plain_s2s
            if try_plain_s2s(sock, addr, a, peek):
                handled = True
                return
        except Exception:
            pass

        handle_client(sock, addr, a)
        handled = True
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
    finally:
        if handled:
            a.release_connection()
        else:
            a.release_connection()


def _s2s_encrypted(msg, reply, sock, addr, a):
    from dmcd.s2s_handler import process_s2s_message
    process_s2s_message(msg, reply, sock, addr, a)


# ---------------------------------------------------------------------------
# Background maintenance
# ---------------------------------------------------------------------------

def cleanup_tasks(a):
    while True:
        time.sleep(60)
        try:
            _run_cleanup(a)
        except Exception as e:
            log_message(f"cleanup error: {e}")


def _run_cleanup(a):
    from dmcd.commands import kick_remote_host

    now = time.time()

    # Sweep stale dialback cache entries (checker-side cache).
    with a.dialback._lock:
        stale = [
            k for k, (ts, _) in a.dialback._cache.items()
            if now - ts > config.DIALBACK_CACHE_TTL
        ]
        for k in stale:
            del a.dialback._cache[k]

    # Ping remote hosts; drop members of dead ones.
    remote_hosts = set()
    for room_name in a.rooms_store.names():
        for (_, origin_host) in a.rooms.local_members_for_cleanup(room_name):
            if origin_host and origin_host != config.MY_SERVER_HOST:
                remote_hosts.add(origin_host)

    fail_counts = {}
    for host in remote_hosts:
        ok = _s2s_ping(a, host)
        if ok:
            fail_counts.pop(host, None)
        else:
            n = fail_counts.get(host, 0) + 1
            fail_counts[host] = n
            if n >= config.S2S_PING_FAIL_THRESHOLD:
                fail_counts.pop(host, None)
                kick_remote_host(a, host)

    # Check remote user presence and kick ghosts.
    users_by_host = {}
    for room_name in a.rooms_store.names():
        for (username, origin_host) in a.rooms.local_members_for_cleanup(room_name):
            if origin_host and origin_host != config.MY_SERVER_HOST:
                users_by_host.setdefault(origin_host, set()).add(username)

    for host, usernames in users_by_host.items():
        online_map = _check_remote_users_online(a, host, usernames)
        for username in usernames:
            ident = f"{username}@{host}"
            online = bool(online_map.get(username, False))
            try:
                from caps import status as status_cap
                status_cap.notify_status_change(ident, online)
            except Exception:
                pass
            if not online:
                from dmcd.commands import _kick_user
                _kick_user(a, ident)

    _cleanup_orphans(a)


def _s2s_ping(a, host) -> bool:
    try:
        out = a.s2s.send_json(
            host,
            {"type": "s2s_ping", "from_host": a.get_advertised_host()},
            timeout=config.S2S_PING_TIMEOUT,
        )
        return isinstance(out, dict) and out.get("status") == "ok"
    except Exception:
        return False


def _check_remote_users_online(a, host, usernames):
    if not usernames:
        return {}
    try:
        out = a.s2s.send_json(
            host,
            {
                "type": "status_request",
                "usernames": list(usernames),
                "from_host": a.get_advertised_host(),
            },
            timeout=5,
        )
        if not isinstance(out, dict) or out.get("status") != "ok":
            return {u: False for u in usernames}
        return out.get("online_map", {})
    except Exception:
        return {u: False for u in usernames}


def _cleanup_orphans(a):
    """Remove room members whose sessions are gone."""
    active = {}
    with a.sessions.lock:
        for room, sessions in a.sessions.by_room.items():
            active[room] = {s.username for s in sessions if s.username}

    for room_name in a.rooms_store.names():
        for (username, origin_host) in a.rooms.local_members_for_cleanup(room_name):
            if origin_host == config.MY_SERVER_HOST:
                if username not in active.get(room_name, set()):
                    last = a.rooms.remove_member(room_name, username, origin_host)
                    a.rooms_store.remove_member(room_name, username)
                    if last:
                        from dmcd.rooms import broadcast_message, format_room_event_text
                        text = format_room_event_text(
                            config.MY_SERVER_HOST, "left", username, origin_host
                        )
                        broadcast_message(
                            text, room_name,
                            sender=username,
                            filter_fn=a.should_filter_message,
                        )
            else:
                subs = a.rooms.remote_subscribers(room_name)
                if origin_host not in subs:
                    a.rooms.remove_member(room_name, username, origin_host)
