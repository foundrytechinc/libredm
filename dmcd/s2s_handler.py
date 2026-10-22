"""Inbound S2S message processing with dialback enforcement."""

from dmcd import config
from dmcd.rooms import (
    format_room_event_text,
    broadcast_message,
)
from dmcd.s2s import generate_msg_id, log_message
from dmcd.sessions import send_to_client
from dmcd.sanitize import sanitize_text, strip_controls


def _close(sock):
    try:
        sock.close()
    except Exception:
        pass


def _client_ip(client_address):
    if isinstance(client_address, tuple) and client_address:
        return str(client_address[0])
    return str(client_address)


def process_s2s_message(msg, reply, sock, client_address, a):
    ip = _client_ip(client_address)
    if not a.s2s_limiter.allow(ip):
        reply({"status": "error", "reason": "rate_limited"})
        _close(sock)
        return

    if not isinstance(msg, dict):
        reply({"status": "error", "reason": "bad_request"})
        _close(sock)
        return

    msg_type = msg.get("type")
    from_host = msg.get("from_host")
    msg_id = msg.get("msg_id")

    # Capability probe is unauthenticated by design (discovery only).
    if msg_type != "s2s_cap" and config.S2S_REQUIRE_SIGNATURE:
        identity = getattr(a, "s2s_identity", None)
        if identity is None or not identity.verify_message(msg, from_host):
            reply({"status": "error", "reason": "signature_invalid"})
            _close(sock)
            return

    if msg_type == "s2s_cap":
        reply({"status": "ok", "encrypted": True})
        _close(sock)
        return

    if msg_type == "dialback_check":
        # Real verification: only confirm messages we actually originated.
        ok = a.outbound_dialback.verify(
            msg_id,
            msg.get("msg_type"),
            sender=msg.get("sender"),
            recipient=msg.get("recipient"),
            room=msg.get("room"),
            event=msg.get("event"),
        )
        reply({"type": "dialback_result", "msg_id": msg_id, "result": "ok" if ok else "fail"})
        _close(sock)
        return

    if msg_type == "s2s_ping":
        reply({"status": "ok"})
        _close(sock)
        return

    if msg_type == "status_request":
        usernames = msg.get("usernames")
        if not isinstance(usernames, list):
            usernames = [msg.get("username", "")] if msg.get("username") else []
        usernames = [u for u in usernames[: config.S2S_MAX_USERNAMES_PER_REQUEST] if isinstance(u, str)]
        online_map = {u: a.sessions.is_user_online(u) for u in usernames}
        reply({"status": "ok", "online_map": online_map})
        _close(sock)
        return

    if msg_type == "remote_pm":
        def async_dialback():
            try:
                ok = a.dialback.check(
                    from_host, msg_id, "remote_pm",
                    sender=msg.get("sender"),
                    recipient=msg.get("recipient"),
                )
                if not ok:
                    reply({"status": "error", "reason": "Dialback failed"})
                    _close(sock)
                    return
                sender = strip_controls(str(msg.get("sender") or ""))[: config.MAX_USERNAME_LENGTH]
                recipient = strip_controls(str(msg.get("recipient") or ""))[: config.MAX_USERNAME_LENGTH]
                message = sanitize_text(str(msg.get("message") or ""))
                if not sender or not recipient or not message:
                    reply({"status": "error", "reason": "bad_request"})
                    _close(sock)
                    return
                if not a.users.exists(recipient):
                    reply({"status": "error", "reason": "user_not_found"})
                    _close(sock)
                    return
                from dmcd.commands import deliver_remote_pm
                delivered = deliver_remote_pm(a, sender, recipient, message, from_host=from_host)
                if delivered:
                    reply({"status": "ok"})
                else:
                    reply({"status": "error", "reason": "failed"})
                _close(sock)
            except Exception:
                try:
                    reply({"status": "error", "reason": "Internal error"})
                    _close(sock)
                except Exception:
                    pass

        if not a.task_pool.submit(async_dialback):
            reply({"status": "error", "reason": "busy"})
            _close(sock)
        return

    if msg_type in ("presence_subscribe", "presence_unsubscribe", "presence_update"):
        def async_presence():
            try:
                ok = a.dialback.check(from_host, msg_id, msg_type)
                if not ok:
                    reply({"status": "error", "reason": "Dialback failed"})
                    _close(sock)
                    return
                try:
                    from caps import status as status_cap
                    if msg_type == "presence_subscribe":
                        status_cap.handle_presence_subscribe(
                            from_host, msg.get("subscriber"), msg.get("target")
                        )
                    elif msg_type == "presence_unsubscribe":
                        status_cap.handle_presence_unsubscribe(
                            from_host, msg.get("subscriber"), msg.get("target")
                        )
                    elif msg_type == "presence_update":
                        status_cap.handle_presence_update(
                            from_host, msg.get("user"), msg.get("online")
                        )
                except Exception:
                    pass
                reply({"status": "ok"})
                _close(sock)
            except Exception:
                try:
                    reply({"status": "error", "reason": "Internal error"})
                    _close(sock)
                except Exception:
                    pass

        if not a.task_pool.submit(async_presence):
            reply({"status": "error", "reason": "busy"})
            _close(sock)
        return

    if msg_type in (
        "room_join", "room_leave", "room_message", "room_act",
        "room_members_request", "room_event",
    ):
        def _room_worker():
            try:
                room = msg.get("room")
                sender = msg.get("sender", "")

                # Dialback: peer must prove it originated this message.
                # Compare against the original fields (do not sanitize first).
                ok = a.dialback.check(
                    from_host, msg_id, msg_type,
                    sender=sender if msg_type != "room_members_request" else None,
                    room=room,
                    event=msg.get("event") if msg_type == "room_event" else None,
                )
                if not ok:
                    reply({"status": "error", "reason": "Dialback failed"})
                    _close(sock)
                    return

                sender = strip_controls(str(sender or ""))[: config.MAX_USERNAME_LENGTH]

                if msg_type == "room_event":
                    _handle_room_event(a, msg, from_host, reply, sock)
                    return

                if msg_type == "room_members_request":
                    members = [
                        {"username": u, "origin": h}
                        for (u, h) in a.rooms.members_map(room).keys()
                    ]
                    reply({
                        "status": "ok", "type": "room_members_response",
                        "room": room, "members": members,
                    })
                    _close(sock)
                    return

                if msg_type == "room_join":
                    if not a.rooms_store.exists(room):
                        reply({"status": "error", "reason": "room_not_found"})
                        _close(sock)
                        return
                    first = a.rooms.add_member(room, sender, from_host)
                    a.rooms.update_remote_subscriber(room, from_host)
                    if first:
                        _broadcast_local(a, room, "joined", sender, from_host)
                        _fanout_remotes(a, room, "joined", sender, from_host)
                    reply({"status": "ok"})
                    _close(sock)
                    return

                if msg_type == "room_leave":
                    if not a.rooms.member_exists(room, sender, from_host):
                        reply({"status": "error", "reason": "not_in_room"})
                        _close(sock)
                        return
                    last = a.rooms.remove_member(room, sender, from_host)
                    a.rooms.update_remote_subscriber(room, from_host)
                    if last:
                        _broadcast_local(a, room, "left", sender, from_host)
                        _fanout_remotes(a, room, "left", sender, from_host)
                    reply({"status": "ok"})
                    _close(sock)
                    return

                if msg_type in ("room_message", "room_act"):
                    if not a.rooms.member_exists(room, sender, from_host):
                        reply({"status": "error", "reason": "not_in_room"})
                        _close(sock)
                        return
                    payload = msg.get("payload") or {}
                    if not isinstance(payload, dict):
                        payload = {}
                    if "text" in payload:
                        payload = dict(payload)
                        payload["text"] = sanitize_text(str(payload.get("text") or ""))
                    if "act" in payload:
                        payload = dict(payload)
                        payload["act"] = sanitize_text(str(payload.get("act") or ""), 200)
                    event = "message" if msg_type == "room_message" else "act"
                    _broadcast_local(a, room, event, sender, from_host, payload)
                    _fanout_remotes(a, room, event, sender, from_host, payload)
                    reply({"status": "ok"})
                    _close(sock)
                    return

            except Exception:
                try:
                    reply({"status": "error", "reason": "Internal error"})
                    _close(sock)
                except Exception:
                    pass

        cached = a.dialback.cached(from_host, msg_type) if from_host else None
        if cached is False:
            # Recent failed dialback — reject immediately without another round-trip.
            reply({"status": "error", "reason": "Dialback failed"})
            _close(sock)
            return
        if not a.task_pool.submit(_room_worker):
            reply({"status": "error", "reason": "busy"})
            _close(sock)
        return

    reply({"status": "error", "reason": "unknown_type"})
    _close(sock)


def _handle_room_event(a, msg, from_host, reply, sock):
    event = msg.get("event")
    sender = strip_controls(str(msg.get("sender") or ""))[: config.MAX_USERNAME_LENGTH]
    sender_origin = msg.get("sender_origin") or from_host
    payload = msg.get("payload") or {}
    if not isinstance(payload, dict):
        payload = {}
    else:
        payload = dict(payload)
    if "text" in payload:
        payload["text"] = sanitize_text(str(payload.get("text") or ""))
    if "act" in payload:
        payload["act"] = sanitize_text(str(payload.get("act") or ""), 200)
    room = msg.get("room")

    if from_host != config.MY_SERVER_HOST and (sender, sender_origin) in a.rooms.members_map(room):
        room_key = room
    elif from_host != config.MY_SERVER_HOST:
        room_key = f"{room}@{from_host}"
    else:
        room_key = room

    exclude = None
    if sender_origin == config.MY_SERVER_HOST and event in ("message", "act"):
        exclude = sender

    _broadcast_local(a, room, event, sender, sender_origin, payload,
                     room_key=room_key, exclude_username=exclude)

    if event in ("message", "act") and sender_origin != config.MY_SERVER_HOST:
        a.task_pool.submit_thread(
            _fanout_remotes, a, room, event, sender, sender_origin, payload
        )
    reply({"status": "ok"})
    _close(sock)


def _broadcast_local(a, room, event, username, origin_host, payload=None,
                     room_key=None, exclude_username=None):
    try:
        text = format_room_event_text(config.MY_SERVER_HOST, event, username, origin_host, payload)
        target_key = room_key or room
        message_type = "room_event" if event in ("message", "act") else "system"
        sender = (
            f"{username}@{origin_host}"
            if (origin_host and origin_host != config.MY_SERVER_HOST)
            else username
        )
        broadcast_message(
            text, target_key,
            message_type=message_type,
            sender=sender,
            exclude_username=exclude_username,
            filter_fn=a.should_filter_message,
        )
    except Exception:
        pass


def _fanout_remotes(a, room, event, username, origin_host, payload=None):
    subs = a.rooms.remote_subscribers(room)
    text = ""
    if payload:
        text = payload.get("text") or payload.get("act") or ""
    data = {
        "type": "room_event",
        "room": room,
        "event": event,
        "sender": username,
        "sender_origin": origin_host,
        "from_host": config.MY_SERVER_HOST,
        "payload": payload or {},
        "msg_id": generate_msg_id(username, room, f"{event}:{text}"),
    }
    for host in subs:
        if host == config.MY_SERVER_HOST:
            continue
        try:
            a.s2s.send_json(host, data, wait_response=False)
        except Exception:
            pass
