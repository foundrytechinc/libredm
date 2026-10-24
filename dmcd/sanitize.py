"""Input sanitization: usernames, chat text, room names.

Strips ANSI escapes, C0/C1 controls, and bidi-override characters so
user-controlled strings cannot inject fake lines or terminal sequences
into other clients.
"""

import re
import unicodedata

from dmcd import config

# ESC + CSI/OSC-style sequences, and bare C0 controls except TAB.
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"   # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC
    r"|\x1b[@-Z\\-_]"              # other ESC finals
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"   # C0 + DEL (keep \t \n \r for now)
    r"|[\x80-\x9f]"                # C1
)

# Bidi overrides / isolates / zero-width that can spoof display.
_BIDI_RE = re.compile(
    r"[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2028\u2029\ufeff]"
)

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def strip_controls(text: str) -> str:
    """Remove ANSI escapes, C0/C1 controls, and bidi overrides."""
    if not text:
        return ""
    text = _ANSI_RE.sub("", text)
    text = _BIDI_RE.sub("", text)
    # Normalize any leftover line breaks to spaces so a single protocol
    # message cannot inject extra chat lines.
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return text


def sanitize_text(text: str, max_len: int = None) -> str:
    """Sanitize a display/message string and cap its length."""
    if not isinstance(text, str):
        return ""
    if max_len is None:
        max_len = config.MAX_MESSAGE_LENGTH
    text = strip_controls(text)
    text = unicodedata.normalize("NFC", text)
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len]
    return text


def sanitize_username(username: str) -> str:
    """Return a safe username, or '' if invalid.

    Accepts 1-64 chars of [A-Za-z0-9._-] starting with alphanumeric.
    """
    if not isinstance(username, str):
        return ""
    username = strip_controls(username).replace("@", "_").replace(" ", "")
    if not username or len(username) > config.MAX_USERNAME_LENGTH:
        return ""
    if not _USERNAME_RE.fullmatch(username):
        return ""
    return username


def is_reserved_username(username: str) -> bool:
    """True for admin / service names that must not be registered."""
    if not username:
        return True
    reserved = {config.ADMIN_USERNAME, "admin", "system", "server", "root"}
    return username.casefold() in {r.casefold() for r in reserved}


def sanitize_room_name(name: str) -> str:
    """Safe local room/server directory name.

    '@' is rejected: room@host is the federation syntax, so a local name
    containing '@' would be misparsed as a remote room.
    """
    if not isinstance(name, str):
        return ""
    name = strip_controls(name)
    name = name.replace("/", "_").replace("\\", "_").replace("\x00", "")
    name = name.replace("@", "_")
    name = name.replace("..", "_")
    name = name.strip(".")
    return name[: config.MAX_USERNAME_LENGTH] or ""
