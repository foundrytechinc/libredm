"""Capability: list active session IPs for the logged-in account."""

from caps.caps import Capability


class SessionsCapability(Capability):
    def __init__(self):
        super().__init__(
            name="sessions",
            commands={"list": "- Show IP addresses of active sessions for your account"},
        )

    def handle_list(self, args, session, client_socket, client_key, server_context=None):
        if not session or not getattr(session, "username", None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True

        username = session.username
        current_ip = None
        try:
            current_ip = client_socket.getpeername()[0]
        except Exception:
            pass

        if server_context and "app" in server_context:
            user_sessions = server_context["app"].sessions.user_sessions(username)
        else:
            from dmcd.app import app
            user_sessions = app.sessions.user_sessions(username)

        ips = []
        seen = set()
        for sess in user_sessions:
            try:
                ip = sess.client_socket.getpeername()[0]
            except Exception:
                continue
            if not ip or ip in seen:
                continue
            seen.add(ip)
            ips.append(ip)

        if not ips:
            self.send_message("No active sessions found.", client_socket, client_key)
            return True

        formatted = []
        for ip in sorted(ips):
            if current_ip and ip == current_ip:
                formatted.append(f"{ip} (this is you)")
            else:
                formatted.append(ip)

        self.send_message("Active session IPs: " + ", ".join(formatted), client_socket, client_key)
        return True
