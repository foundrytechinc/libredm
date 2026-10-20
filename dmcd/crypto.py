"""Cryptography: password hashing, AES-ETM, Diffie-Hellman.

Uses the C hot-path module (dmcd/native) when available, otherwise
falls back to pycryptodome + hashlib.
"""

import hashlib
import hmac
import os
import re
import struct
import threading

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from dmcd import config

try:
    from dmcd.native import dmcd_native as _native
except Exception:
    _native = None

# RFC 5114 1024-bit MODP Group (same group as the original protocol)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Return a PBKDF2-SHA256 hash string: pbkdf2_sha256$iters$salt$hash."""
    salt = get_random_bytes(16)
    pw = password.encode("utf-8")
    if _native is not None:
        dk = _native.pbkdf2_sha256(pw, salt, config.PBKDF2_ITERATIONS)
    else:
        dk = hashlib.pbkdf2_hmac("sha256", pw, salt, config.PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        config.PBKDF2_ITERATIONS, salt.hex(), dk.hex()
    )


def _verify_pbkdf2(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        if iters < 50_000 or iters > 10_000_000:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        pw = password.encode("utf-8")
        if _native is not None:
            dk = _native.pbkdf2_sha256(pw, salt, iters)
        else:
            dk = hashlib.pbkdf2_hmac("sha256", pw, salt, iters)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def _verify_legacy(password: str, stored: str) -> bool:
    """Verify against legacy plain / md5 / sha256 / sha512 / base64 forms.

    Only used to migrate old users.json entries. On success the caller should
    re-hash with hash_password().
    """
    if stored == password:
        return True
    # md5
    if len(stored) == 32 and re.fullmatch(r"[a-fA-F0-9]{32}", stored):
        return hmac.compare_digest(
            hashlib.md5(password.encode("utf-8")).hexdigest().lower(), stored.lower()
        )
    # sha256
    if len(stored) == 64 and re.fullmatch(r"[a-fA-F0-9]{64}", stored):
        return hmac.compare_digest(
            hashlib.sha256(password.encode("utf-8")).hexdigest().lower(), stored.lower()
        )
    # sha512
    if len(stored) == 128 and re.fullmatch(r"[a-fA-F0-9]{128}", stored):
        return hmac.compare_digest(
            hashlib.sha512(password.encode("utf-8")).hexdigest().lower(), stored.lower()
        )
    return False


def verify_password(password: str, stored: str) -> bool:
    if not isinstance(stored, str) or not isinstance(password, str):
        return False
    if stored.startswith("pbkdf2_sha256$"):
        return _verify_pbkdf2(password, stored)
    return _verify_legacy(password, stored)


def needs_rehash(stored: str) -> bool:
    return not (isinstance(stored, str) and stored.startswith("pbkdf2_sha256$"))


# ---------------------------------------------------------------------------
# Session key derivation
# ---------------------------------------------------------------------------

def derive_session_keys(shared_bytes: bytes):
    enc_key = hashlib.sha256(shared_bytes + b"|KEY").digest()
    mac_key = hashlib.sha256(shared_bytes + b"|MAC").digest()
    return enc_key, mac_key


# ---------------------------------------------------------------------------
# AES-CBC + HMAC-SHA256 (Encrypt-then-MAC)
# ---------------------------------------------------------------------------

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("bad padding length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("bad padding value")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("bad padding bytes")
    return data[:-pad_len]


def encrypt_message(message: str, enc_key: bytes, mac_key: bytes) -> bytes:
    """Encrypt message. Returns iv || ciphertext || hmac(mac_key, iv||ciphertext)."""
    plain = message.encode("utf-8")
    if _native is not None:
        return _native.aead_encrypt(enc_key, mac_key, plain)
    iv = get_random_bytes(config.IV_SIZE)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(_pkcs7_pad(plain))
    body = iv + ct
    mac = hmac.new(mac_key, body, hashlib.sha256).digest()
    return body + mac


def decrypt_message(data: bytes, enc_key: bytes, mac_key: bytes) -> str:
    """Verify HMAC then decrypt. Raises ValueError on tampering/bad padding."""
    if len(data) < config.IV_SIZE + 16 + config.MAC_SIZE:
        raise ValueError("ciphertext too short")
    if _native is not None:
        return _native.aead_decrypt(enc_key, mac_key, data).decode("utf-8")
    body, mac = data[:-config.MAC_SIZE], data[-config.MAC_SIZE:]
    expected = hmac.new(mac_key, body, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("HMAC verification failed")
    iv, ct = body[:config.IV_SIZE], body[config.IV_SIZE:]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    plain = _pkcs7_unpad(cipher.decrypt(ct))
    return plain.decode("utf-8")


def send_encrypted(sock, message: str, enc_key: bytes, mac_key: bytes) -> bool:
    try:
        payload = encrypt_message(message, enc_key, mac_key)
        sock.sendall(struct.pack(">I", len(payload)) + payload)
        return True
    except Exception:
        return False


def receive_encrypted(sock, enc_key: bytes, mac_key: bytes, max_packet: int = None) -> str:
    max_packet = max_packet or config.MAX_PACKET_SIZE
    try:
        length_data = _recv_exact(sock, 4)
        if length_data is None:
            return None
        length = struct.unpack(">I", length_data)[0]
        if length <= 0 or length > max_packet + config.MAC_SIZE + config.IV_SIZE + 16:
            return None
        payload = _recv_exact(sock, length)
        if payload is None:
            return None
        return decrypt_message(payload, enc_key, mac_key)
    except Exception:
        return None


def _recv_exact(sock, n: int):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Diffie-Hellman
# ---------------------------------------------------------------------------

class DHContext:
    """One side of a DH exchange."""

    def __init__(self):
        self._priv = int.from_bytes(get_random_bytes(32), "big")

    def public_bytes(self) -> bytes:
        val = pow(DH_G, self._priv, DH_P)
        length = (DH_P.bit_length() + 7) // 8
        raw = val.to_bytes(length, "big").lstrip(b"\x00") or b"\x00"
        return raw

    def shared_secret(self, peer_public_bytes: bytes) -> bytes:
        peer = int.from_bytes(peer_public_bytes, "big")
        # Match original: no subgroup checks, same serialization.
        shared = pow(peer, self._priv, DH_P)
        length = (DH_P.bit_length() + 7) // 8
        raw = shared.to_bytes(length, "big")
        return raw.lstrip(b"\x00") or b"\x00"


def dh_send_public(sock, public_bytes: bytes):
    sock.sendall(struct.pack(">H", len(public_bytes)) + public_bytes)


def _parse_length_prefixed(len_bytes: bytes) -> int:
    """Accept both >H (original) and >I (4-byte) length prefixes.

    Also tolerates little-endian 2-byte lengths from third-party clients.
    """
    if len(len_bytes) < 2:
        raise ConnectionError("DH length missing")
    n = struct.unpack(">H", len_bytes[:2])[0]
    if 1 <= n <= 512:
        return n
    # 4-byte BE length with high half already consumed (e.g. 00 00 00 80)
    if n == 0 and len(len_bytes) >= 4:
        n2 = struct.unpack(">H", len_bytes[2:4])[0]
        if 1 <= n2 <= 512:
            return n2
    # little-endian 2-byte length (e.g. 80 00 -> 128)
    n_le = struct.unpack("<H", len_bytes[:2])[0]
    if 1 <= n_le <= 512:
        return n_le
    raise ConnectionError("DH length invalid")


def dh_recv_public(sock) -> bytes:
    """Read a peer DH public value. Accepts original 2-byte and 4-byte lengths."""
    first = _recv_exact(sock, 2)
    if not first:
        raise ConnectionError("DH length missing")
    n = struct.unpack(">H", first)[0]
    if n == 0:
        # Maybe a 4-byte length prefix (0x000000xx) — read the low half.
        rest = _recv_exact(sock, 2)
        if not rest:
            raise ConnectionError("DH length missing")
        blen = _parse_length_prefixed(first + rest)
    elif 1 <= n <= 512:
        blen = n
    else:
        # Could be LE length, or we are out of sync with a text client.
        try:
            blen = _parse_length_prefixed(first)
        except ConnectionError:
            raise ConnectionError("DH length invalid")
    raw = _recv_exact(sock, blen)
    if not raw:
        raise ConnectionError("DH public truncated")
    return raw


def dh_client(sock):
    """Client side: receive A, send B, return (enc_key, mac_key)."""
    a_bytes = dh_recv_public(sock)
    ctx = DHContext()
    dh_send_public(sock, ctx.public_bytes())
    return derive_session_keys(ctx.shared_secret(a_bytes))


def dh_server(sock, client_first: bool = False):
    """Server side of the handshake.

    Original order is server-first (send A, then read B). If the peer
    already sent its public value (client-first), pass client_first=True
    or let the caller read it first.
    """
    ctx = DHContext()
    if client_first:
        b_bytes = dh_recv_public(sock)
        dh_send_public(sock, ctx.public_bytes())
    else:
        dh_send_public(sock, ctx.public_bytes())
        b_bytes = dh_recv_public(sock)
    return derive_session_keys(ctx.shared_secret(b_bytes))
