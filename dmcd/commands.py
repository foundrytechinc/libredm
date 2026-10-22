"""Chat command handlers (everything after login)."""

import re

from dmcd import __version__, config
from dmcd import crypto
from dmcd.rooms import (
    display_name_for,
    format_room_event_text,
    parse_room_and_host,
    broadcast_message,
)
from dmcd.sessions import send_to_client
from dmcd.s2s import generate_msg_id, log_message
from dmcd.sanitize import sanitize_room_name, sanitize_text


COMMANDS = {
    "/login": "<username> <password> - Login with username and password.",
    "/register": "<username> <password> - Register a new user.",
    "/create_server": "<server name> - Create a new communication server.",
    "/join_server": "<server name> - Log in to the communication server.",
    "/list_servers": "- Get a list of all available servers for communication.",
    "/members": "- Get list of users on server.",
    "/pm": "<username> <message> - Send a private message to the specified user.",
    "/act": "<action> - Chat action, set your status.",
    "/history": "[limit] - Show recent messages (default: 50, SQLite only).",
    "/search": "<keyword> - Search messages (SQLite only).",
    "/list_capabilities": "- Get a list of all available capabilities.",
    "/help": "- Shows this message.",
}

# Core commands; anything else falls through to the capabilities manager.
CORE_PREFIXES = (
    "/login", "/register", "/create_server", "/join_server", "/list_servers",
    "/members", "/pm", "/act", "/help", "/list_capabilities", "/ban",
    "/delete_server", "/history", "/search",
)


def is_ping(text: str) -> bool:
    return bool(text) and all(ch == "/" for ch in text)


def is_at_command(text: str) -> bool:
    if not text:
        return False
    t = text.strip()
    if len(t) < 2 or t[:3].upper() != "AT ":
        return False
    rest = t[2:]
    if rest and rest[0] in " &":
        rest = rest[1:].lstrip()
    if not rest:
        return True
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=,;.+*- ")
    return all(ch.upper() in allowed for ch in rest)


def get_safe_server_path(server_name: str) -> str:
    return sanitize_room_name(server_name) or "server"


class CommandContext:
    def __init__(self, a, session, client_key):
        self.app = a
        self.session = session
        self.client_key = client_key
        self.username = session.username
        self.user_server = session.server_name

    def reply(self, message: str):
        send_to_client(self.session.client_socket, message, self.client_key)

    def room_name_and_host(self):
        return parse_room_and_host(self.user_server or "")


def handle_command(message: str, ctx: CommandContext) -> None:
    """Dispatch a slash-command. Non-slash messages must not reach here."""
    a = ctx.app

    if is_ping(message):
        ctx.reply("*Ping!*")
        return

    if message.startswith("/create_server"):
        _cmd_create_server(message, ctx)
    elif message.startswith("/join_server"):
        _cmd_join_server(message, ctx)
    elif message.startswith("/delete_server") and ctx.username == config.ADMIN_USERNAME:
        _cmd_delete_server(message, ctx)
    elif message.startswith("/list_servers"):
        ctx.reply(f"Servers: {', '.join(a.rooms_store.names())}")
    elif message.startswith("/members"):
        _cmd_members(ctx)
    elif message.startswith("/ban") and ctx.username == config.ADMIN_USERNAME:
        _cmd_ban(message, ctx)
    elif message.startswith("/act"):
        _cmd_act(message, ctx)
    elif message.startswith("/pm"):
        _cmd_pm(message, ctx)
    elif message.startswith("/history"):
        _cmd_history(message, ctx)
    elif message.startswith("/search"):
        _cmd_search(message, ctx)
    elif message.startswith("/help"):
        ctx.reply(f"LibreDM {__version__}\n" + "\n".join(f"{cmd} {desc}" for cmd, desc in COMMANDS.items()))
    elif message.startswith("/list_capabilities"):
        _cmd_list_capabilities(ctx)
    elif message.startswith("/") and not is_ping(message) and not any(
        message.startswith(p) for p in CORE_PREFIXES
    ):
        _cmd_capability(message, ctx)
    else:
        ctx.reply("Unknown command.")


def handle_chat_message(message: str, ctx: CommandContext) -> None:
    a = ctx.app
    if not ctx.username or not ctx.user_server:
        return
    if a.bans.is_banned(ctx.username):
        return
    message = sanitize_text(message)
    if not message:
        return
    room_name, host_part = ctx.room_name_and_host()
    if host_part and host_part != config.MY_SERVER_HOST:
        _echo_room_event(ctx, "message", ctx.username, config.MY_SERVER_HOST, {"text": message})
        payload = {
            "type": "room_message",
            "room": room_name,
            "sender": ctx.username,
            "payload": {"text": message},
        }
        _send_remote_room_async(a, host_part, room_name, payload)
    else:
        full_message = f"{ctx.username}: {message}"
        broadcast_message(
            full_message,
            ctx.user_server,
            message_type="chat_message",
            sender=ctx.username,
            filter_fn=a.should_filter_message,
        )
        # Save message to history if SQLite is enabled
        if a.messages:
            try:
                a.messages.save_message(room_name, ctx.username, message, config.MY_SERVER_HOST)
            except Exception as e:
                log_message(f"Failed to save message to history: {e}")
        a.task_pool.submit_thread(
            _send_room_event_to_remotes,
            a, room_name, "message", ctx.username, config.MY_SERVER_HOST, {"text": message},
        )


# ---------------------------------------------------------------------------
# Individual commands
# ---------------------------------------------------------------------------

def _cmd_create_server(message, ctx):
    parts = message.split(" ", 1)
    if len(parts) != 2:
        ctx.reply("Usage: /create_server <server_name>")
        return
    server_name = get_safe_server_path(parts[1])
    if ctx.app.rooms_store.create(server_name):
        ctx.reply(f"Server '{server_name}' created successfully.")
    else:
        ctx.reply("Server already exists.")


def _cmd_delete_server(message, ctx):
    parts = message.split(" ", 1)
    if len(parts) != 2:
        ctx.reply("Usage: /delete_server <server_name>")
        return
    server_name = get_safe_server_path(parts[1])
    if server_name == config.DEFAULT_SERVER:
        ctx.reply(f"You cannot delete the default server '{config.DEFAULT_SERVER}'.")
        return
    if ctx.app.rooms_store.delete(server_name):
        ctx.reply(f"Server '{server_name}' deleted successfully.")
    else:
        ctx.reply(f"Server '{server_name}' does not exist.")


def _cmd_join_server(message, ctx):
    a = ctx.app
    parts = message.split(" ", 1)
    if len(parts) != 2:
        ctx.reply("Usage: /join_server <server_name>")
        return
    if ctx.user_server is not None:
        ctx.reply(f"You're already connected to the server '{ctx.user_server}'.")
        return
    server_spec = parts[1]
    room_name, host_part = parse_room_and_host(server_spec)

    if host_part and host_part != config.MY_SERVER_HOST:
        remote_key = (ctx.username, room_name, host_part)
        need_room_join = a.rooms.remote_counter(remote_key) == 0
        if need_room_join:
            ok, reason = _remote_join_room(a, host_part, room_name, ctx.username)
            if not ok:
                ctx.reply("Server does not exist.")
                return
        a.rooms.remote_counter_inc(remote_key)
        user_server = f"{room_name}@{host_part}"
        a.sessions.set_room(ctx.session, user_server)
        ctx.reply(f"Joined server '{user_server}' successfully.")
        return

    local_room = room_name
    if not a.rooms_store.exists(local_room):
        ctx.reply("Server does not exist.")
        return

    user_server = local_room
    sessions = a.sessions.room_sessions(local_room)
    had_same_user = any(s.username == ctx.username for s in sessions)
    a.sessions.set_room(ctx.session, local_room)
    first_ref = a.rooms.add_member(local_room, ctx.username, config.MY_SERVER_HOST)
    should_announce = first_ref and not had_same_user
    if should_announce:
        a.rooms_store.add_member(local_room, ctx.username)
        join_text = f"*** {ctx.username} has joined the server."
        broadcast_message(
            join_text, user_server, sender=ctx.username, filter_fn=a.should_filter_message
        )
        try:
            a.task_pool.submit_thread(
                _send_room_event_to_remotes,
                a, local_room, "joined", ctx.username, config.MY_SERVER_HOST, None,
            )
        except Exception:
            pass
    ctx.reply(f"Joined server '{local_room}' successfully.")


def _cmd_members(ctx):
    a = ctx.app
    if not (ctx.username and ctx.user_server):
        ctx.reply("Please log in and join a server first.")
        return
    room_name, host_part = ctx.room_name_and_host()
    if host_part and host_part != config.MY_SERVER_HOST:
        req = {"type": "room_members_request", "room": room_name, "msg_id": generate_msg_id(ctx.username, room_name, "members")}
        resp = _send_remote_room_sync(a, host_part, req)
        if not resp or resp.get("status") != "ok":
            ctx.reply("Failed to fetch members.")
            return
        members_raw = resp.get("members", [])
        disp = [display_name_for(config.MY_SERVER_HOST, m["username"], m["origin"]) for m in members_raw]
        ctx.reply(f"Members in '{ctx.user_server}': {', '.join(disp)}")
    else:
        names = a.rooms.member_names(room_name, config.MY_SERVER_HOST)
        ctx.reply(f"Members in '{ctx.user_server}': {', '.join(names)}")


def _cmd_ban(message, ctx):
    a = ctx.app
    parts = message.split(" ", 1)
    if len(parts) != 2:
        ctx.reply("Usage: /ban <username>")
        return
    banned_user = parts[1]
    with a.sessions.lock:
        user_sessions = list(a.sessions.by_user.get(banned_user, set()))
        for sess in user_sessions:
            try:
                if sess.server_name:
                    a.sessions.set_room(sess, None)
                sess.client_socket.close()
            except Exception:
                pass
        a.sessions.by_user.pop(banned_user, None)
        for sock, s in list(a.sessions.by_socket.items()):
            if s.username == banned_user:
                a.sessions.by_socket.pop(sock, None)
    a.bans.ban(banned_user)
    ctx.reply(f"User {banned_user} has been banned.")


def _cmd_act(message, ctx):
    a = ctx.app
    parts = message.split(" ", 1)
    if len(parts) < 2:
        if not ctx.username or not ctx.user_server:
            ctx.reply("Please log in and join a server first.")
        else:
            ctx.reply("Usage: /act <act>")
        return
    act_name = sanitize_text(parts[1])
    if not act_name:
        ctx.reply("Usage: /act <act>")
        return
    lowered = act_name.lower()
    if "has joined the server" in lowered or "has left the server" in lowered:
        ctx.reply("This action is not allowed.")
        return
    if not ctx.user_server:
        ctx.reply("Please log in and join a server first.")
        return

    room_name, host_part = ctx.room_name_and_host()
    if host_part and host_part != config.MY_SERVER_HOST:
        _echo_room_event(ctx, "act", ctx.username, config.MY_SERVER_HOST, {"act": act_name})
        payload = {
            "type": "room_act",
            "room": room_name,
            "sender": ctx.username,
            "payload": {"act": act_name},
        }
        _send_remote_room_async(a, host_part, room_name, payload)
    else:
        act_text = f"*** {ctx.username} {act_name}"
        broadcast_message(
            act_text,
            ctx.user_server,
            message_type="action_message",
            sender=ctx.username,
            filter_fn=a.should_filter_message,
        )
        try:
            a.task_pool.submit_thread(
                _send_room_event_to_remotes,
                a, room_name, "act", ctx.username, config.MY_SERVER_HOST, {"act": act_name},
            )
        except Exception:
            pass


def _cmd_pm(message, ctx):
    a = ctx.app
    parts = message.split(" ", 2)
    if len(parts) < 3:
        ctx.reply("Usage: /pm <username> <message>")
        return
    _, recipient, private_message = parts
    private_message = sanitize_text(private_message)
    if not private_message:
        ctx.reply("Usage: /pm <username> <message>")
        return
    m = re.match(r"^([\w\-]+)@([\w.\-]+)$", recipient)
    if m:
        remote_user, remote_host = m.group(1), m.group(2)
        if remote_host == config.MY_SERVER_HOST:
            recipient = remote_user
        else:
            a.task_pool.submit_thread(
                _handle_remote_pm,
                a, ctx, remote_user, remote_host, private_message, recipient,
            )
            return

    if not a.users.exists(recipient):
        ctx.reply("User does not exist.")
        _kick_user(a, recipient)
        return
    if recipient == ctx.username:
        ctx.reply("You cannot send private messages to yourself.")
        return
    if a.bans.is_banned(recipient):
        ctx.reply(f"{recipient} is banned.")
        return

    result = _send_private_message(a, ctx.username, recipient, private_message)
    if not result:
        _kick_user(a, recipient)
    if result:
        ctx.reply(f"Private message sent to {recipient}.")
    else:
        ctx.reply(f"Failed to send private message to {recipient}.")


def _cmd_list_capabilities(ctx):
    caps = ctx.app.capabilities_manager
    if caps is None:
        ctx.reply("No capabilities available.")
        return
    caps_list = caps.get_capabilities_list()
    if caps_list:
        ctx.reply("Capabilities: " + ", ".join(caps_list) + ". Use /CAPABILITY_NAME for help.")
    else:
        ctx.reply("No capabilities available.")


def _cmd_capability(message, ctx):
    a = ctx.app
    cap_command = message[1:]
    parts = cap_command.split()
    if len(parts) > 1:
        command_part, args = parts[0], parts[1:]
    else:
        command_part, args = cap_command, []

    server_context = {
        "clients_by_user": _user_sessions_map(a),
        "clients_by_server": _room_sessions_map(a),
        "socket_to_session": a.sessions.by_socket,
        "session_lock": a.sessions.lock,
        "users": _UsersView(a),
        "bans": _BansView(a),
        "servers": _ServersView(a),
        "app": a,
    }
    if a.capabilities_manager and a.capabilities_manager.handle_capability_command(
        command_part, args, ctx.session, ctx.session.client_socket, ctx.client_key, server_context
    ):
        return
    ctx.reply("Unknown command.")


# ---------------------------------------------------------------------------
# Messaging helpers
# ---------------------------------------------------------------------------

def _send_private_message(a, sender_username, recipient_username, message) -> bool:
    if a.should_filter_message(recipient_username, sender_username, "pm"):
        return True
    delivered = False
    recipient_sessions = a.sessions.user_sessions(recipient_username)
    pm_text = f"(Private) {sender_username}: {message}"
    for sess in recipient_sessions:
        ok = send_to_client(sess.client_socket, pm_text, sess.client_key, "private_message")
        delivered = delivered or ok
    return delivered


def _echo_room_event(ctx, event, username, origin_host, payload=None):
    text = format_room_event_text(config.MY_SERVER_HOST, event, username, origin_host, payload)
    send_to_client(ctx.session.client_socket, text, ctx.client_key, "room_event")


def _send_remote_room_async(a, host, room, payload):
    a.task_pool.submit_thread(_send_remote_room_sync, a, host, payload)


def _send_remote_room_sync(a, host, data):
    if "msg_id" not in data:
        data = dict(data)
        data["msg_id"] = generate_msg_id(
            data.get("sender", ""), data.get("room", ""), data.get("type", "")
        )
        data.setdefault("from_host", a.get_advertised_host())
    return a.s2s.send_json(host, data)


def _send_room_event_to_remotes(a, room, event, username, origin_host, payload=None):
    subs = a.rooms.remote_subscribers(room)
    data = {
        "type": "room_event",
        "room": room,
        "event": event,
        "sender": username,
        "sender_origin": origin_host,
        "from_host": config.MY_SERVER_HOST,
        "payload": payload or {},
    }
    text = payload.get("text") or payload.get("act") or event if payload else event
    data["msg_id"] = generate_msg_id(username, room, f"{event}:{text}")
    for host in subs:
        if host == config.MY_SERVER_HOST:
            continue
        try:
            a.s2s.send_json(host, data, wait_response=False)
        except Exception:
            pass


def _remote_join_room(a, host, room, username):
    payload = {
        "type": "room_join",
        "room": room,
        "sender": username,
        "msg_id": generate_msg_id(username, room, "join"),
        "from_host": a.get_advertised_host(),
    }
    try:
        resp = a.s2s.send_json(host, payload)
        if isinstance(resp, dict) and resp.get("status") == "ok":
            a.dialback.cache(host, "room_event", True)
            return True, None
        reason = resp.get("reason") if isinstance(resp, dict) else None
        return False, reason or "unreachable"
    except Exception:
        return False, "unreachable"


def _handle_remote_pm(a, ctx, remote_user, remote_host, private_message, recipient_display):
    try:
        msg_id = generate_msg_id(ctx.username, remote_user, private_message)
        data = {
            "type": "remote_pm",
            "sender": ctx.username,
            "recipient": remote_user,
            "message": private_message,
            "from_host": config.MY_SERVER_HOST,
            "msg_id": msg_id,
        }
        resp = a.s2s.send_json(remote_host, data)
        status = isinstance(resp, dict) and resp.get("status") == "ok"
        if isinstance(resp, dict) and resp.get("reason") == "user_not_found":
            send_to_client(ctx.session.client_socket, "User does not exist.", ctx.client_key)
            _kick_user(a, recipient_display)
            return
        if status:
            send_to_client(ctx.session.client_socket, f"Private message sent to {recipient_display}.", ctx.client_key)
        else:
            send_to_client(ctx.session.client_socket, f"Failed to send private message to {recipient_display}.", ctx.client_key)
            _kick_user(a, recipient_display)
    except Exception:
        send_to_client(ctx.session.client_socket, f"Failed to send private message to {recipient_display}.", ctx.client_key)


def deliver_remote_pm(a, sender, recipient, message, from_host=None) -> bool:
    filter_sender = sender
    sender_display = sender
    if from_host and from_host != config.MY_SERVER_HOST:
        filter_sender = f"{sender}@{from_host}"
        sender_display = filter_sender
    if a.should_filter_message(recipient, filter_sender, "pm"):
        return True
    recipient_sessions = a.sessions.user_sessions(recipient)
    if not recipient_sessions:
        return False
    pm_text = f"(Private) {sender_display}: {message}"
    delivered = False
    for sess in recipient_sessions:
        ok = send_to_client(sess.client_socket, pm_text, sess.client_key, "private_message")
        delivered = delivered or ok
    return delivered


def _kick_user(a, identifier):
    try:
        if "@" in identifier:
            username, host = identifier.rsplit("@", 1)
        else:
            username, host = identifier, None

        for room_name in a.rooms_store.names():
            for (user, origin_host) in a.rooms.local_members_for_cleanup(room_name):
                if user != username:
                    continue
                if host is not None and origin_host != host:
                    continue
                last = a.rooms.remove_member(room_name, user, origin_host)
                if origin_host == config.MY_SERVER_HOST:
                    a.rooms_store.remove_member(room_name, user)
                if origin_host != config.MY_SERVER_HOST and last:
                    text = format_room_event_text(config.MY_SERVER_HOST, "left", user, origin_host)
                    broadcast_message(text, room_name, sender=user, filter_fn=a.should_filter_message)
                    try:
                        a.task_pool.submit_thread(
                            _send_room_event_to_remotes, a, room_name, "left", user, origin_host, None
                        )
                    except Exception:
                        pass
                break
    except Exception as e:
        log_message(f"kick error: {e}")


def kick_remote_host(a, host):
    results = a.rooms.drop_host_members(host)
    for room_name, username, origin_host, was_last in results:
        if was_last:
            text = format_room_event_text(config.MY_SERVER_HOST, "left", username, origin_host)
            broadcast_message(text, room_name, sender=username, filter_fn=a.should_filter_message)
            try:
                a.task_pool.submit_thread(
                    _send_room_event_to_remotes, a, room_name, "left", username, origin_host, None
                )
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Compatibility views for capability plugins (legacy dict-like API)
# ---------------------------------------------------------------------------

def _user_sessions_map(a):
    with a.sessions.lock:
        return {u: set(s) for u, s in a.sessions.by_user.items()}


def _room_sessions_map(a):
    with a.sessions.lock:
        return {r: set(s) for r, s in a.sessions.by_room.items()}


class _UsersView:
    def __init__(self, a):
        self._a = a

    def __contains__(self, k):
        return self._a.users.exists(k)

    def __getitem__(self, k):
        return self._a.users.get_hash(k)

    def get(self, k, default=None):
        return self._a.users.get_hash(k) or default

    def keys(self):
        return self._a.users.usernames()


class _BansView:
    def __init__(self, a):
        self._a = a

    def __contains__(self, k):
        return self._a.bans.is_banned(k)


class _ServersView:
    def __init__(self, a):
        self._a = a

    def __contains__(self, k):
        return self._a.rooms_store.exists(k)

    def keys(self):
        return self._a.rooms_store.names()

    def get(self, k, default=None):
        return self._a.rooms_store.members(k) if self._a.rooms_store.exists(k) else default

    def __getitem__(self, k):
        return self._a.rooms_store.members(k)


def _cmd_history(message, ctx):
    """Show recent message history from the current room (SQLite only)."""
    a = ctx.app
    if not a.messages:
        ctx.reply("History is not available (SQLite backend not enabled).")
        return
    if not ctx.user_server:
        ctx.reply("Please join a server first.")
        return

    parts = message.split()
    limit = 50
    if len(parts) > 1:
        try:
            limit = int(parts[1])
            if limit < 1 or limit > 500:
                ctx.reply("Limit must be between 1 and 500.")
                return
        except ValueError:
            ctx.reply("Invalid limit. Usage: /history [limit]")
            return

    room_name, host_part = ctx.room_name_and_host()
    if host_part and host_part != config.MY_SERVER_HOST:
        ctx.reply("History is only available for local rooms.")
        return

    try:
        messages = a.messages.get_recent_messages(room_name, limit)
        if not messages:
            ctx.reply("No messages in history.")
            return
        lines = [f"--- Last {len(messages)} messages ---"]
        for msg in messages:
            sender = msg["sender"]
            origin = msg.get("origin_host", config.MY_SERVER_HOST)
            text = msg["text"]
            timestamp = msg["sent_at"][:19]  # Strip milliseconds
            if origin == config.MY_SERVER_HOST:
                lines.append(f"[{timestamp}] {sender}: {text}")
            else:
                lines.append(f"[{timestamp}] {sender}@{origin}: {text}")
        ctx.reply("\n".join(lines))
    except Exception as e:
        log_message(f"History error: {e}")
        ctx.reply("Failed to retrieve history.")


def _cmd_search(message, ctx):
    """Search messages in the current room (SQLite only)."""
    a = ctx.app
    if not a.messages:
        ctx.reply("Search is not available (SQLite backend not enabled).")
        return
    if not ctx.user_server:
        ctx.reply("Please join a server first.")
        return

    parts = message.split(None, 1)
    if len(parts) < 2:
        ctx.reply("Usage: /search <keyword>")
        return

    keyword = parts[1]
    room_name, host_part = ctx.room_name_and_host()
    if host_part and host_part != config.MY_SERVER_HOST:
        ctx.reply("Search is only available for local rooms.")
        return

    try:
        messages = a.messages.search_messages(room_name, keyword)
        if not messages:
            ctx.reply(f"No messages found matching '{keyword}'.")
            return
        lines = [f"--- Found {len(messages)} messages ---"]
        for msg in messages:
            sender = msg["sender"]
            origin = msg.get("origin_host", config.MY_SERVER_HOST)
            text = msg["text"]
            timestamp = msg["sent_at"][:19]
            if origin == config.MY_SERVER_HOST:
                lines.append(f"[{timestamp}] {sender}: {text}")
            else:
                lines.append(f"[{timestamp}] {sender}@{origin}: {text}")
        ctx.reply("\n".join(lines))
    except Exception as e:
        log_message(f"Search error: {e}")
        ctx.reply("Failed to search messages.")

