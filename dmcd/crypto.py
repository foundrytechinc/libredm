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

# RFC 3526 2048-bit MODP Group 14 (safe prime) — default.
# Legacy value kept byte-identical to the original protocol for old clients.
_DH_P_LEGACY = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
_DH_P_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_P = _DH_P_LEGACY if getattr(config, "LEGACY_DH_1024", False) else _DH_P_2048
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


def _legacy_digest_ok(password: str, stored: str, algo: str, digest_fn) -> bool:
    """Constant-time compare of an unsalted hex digest. Migration only."""
    try:
        if len(stored) == algo and re.fullmatch(r"[a-fA-F0-9]+", stored):
            expected = digest_fn(password.encode("utf-8")).hexdigest().lower()
            return hmac.compare_digest(expected, stored.lower())
    except Exception:
        return False
    return False


def _verify_legacy(password: str, stored: str) -> bool:
    """Verify against legacy unsalted md5/sha256/sha512 hex digests.

    Used only to migrate old users.json / DB rows. On success the caller
    re-hashes with hash_password(). Plaintext equality is not accepted.

    Original DMCD also had `stored == password` and base64 tricks
    (see 111.py authenticate_user); those are intentionally gone.
    """
    if not config.ALLOW_LEGACY_PASSWORD_HASHES:
        return False
    # md5 (32 hex)
    if _legacy_digest_ok(password, stored, 32, hashlib.md5):
        return True
    # sha256 (64 hex)
    if _legacy_digest_ok(password, stored, 64, hashlib.sha256):
        return True
    # sha512 (128 hex)
    if _legacy_digest_ok(password, stored, 128, hashlib.sha512):
        return True
    return False


def looks_like_legacy_hash(stored: str) -> bool:
    if not isinstance(stored, str) or not stored or stored.startswith("pbkdf2_sha256$"):
        return False
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128}", stored))


def looks_like_plaintext_password(stored: str) -> bool:
    """Stored value is not a recognized hash — old DMCD plaintext."""
    if not isinstance(stored, str) or not stored or stored.startswith("pbkdf2_sha256$"):
        return False
    return not looks_like_legacy_hash(stored)


def verify_password(password: str, stored: str) -> bool:
    if not isinstance(stored, str) or not isinstance(password, str):
        return False
    if stored.startswith("pbkdf2_sha256$"):
        return _verify_pbkdf2(password, stored)
    if config.ALLOW_LEGACY_PLAINTEXT_PASSWORDS and stored == password:
        # Explicit opt-in only (legacy DMCD compatibility). Off by default.
        return True
    return _verify_legacy(password, stored)


def needs_rehash(stored: str) -> bool:
    return not (isinstance(stored, str) and stored.startswith("pbkdf2_sha256$"))


# ---------------------------------------------------------------------------
# Session key derivation
# ---------------------------------------------------------------------------

def derive_session_keys(shared_bytes: bytes):
    if _native is not None:
        return _native.derive_session_keys(shared_bytes)
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

def _dh_modp_bytes() -> bytes:
    length = (DH_P.bit_length() + 7) // 8
    return DH_P.to_bytes(length, "big")


class DHContext:
    """One side of a DH exchange."""

    def __init__(self):
        # 256-bit private exponent is standard and matches the group size class.
        nbytes = getattr(config, "DH_PRIV_BYTES", 32)
        self._priv = int.from_bytes(get_random_bytes(nbytes), "big") or 1
        self._priv_bytes = self._priv.to_bytes(nbytes, "big")
        self._modp = _dh_modp_bytes()

    def public_bytes(self) -> bytes:
        if _native is not None:
            return _native.dh_public(self._priv_bytes, self._modp)
        val = pow(DH_G, self._priv, DH_P)
        length = (DH_P.bit_length() + 7) // 8
        raw = val.to_bytes(length, "big").lstrip(b"\x00") or b"\x00"
        return raw

    def shared_secret(self, peer_public_bytes: bytes) -> bytes:
        if _native is not None:
            _native.dh_validate_public(peer_public_bytes, self._modp)
            return _native.dh_shared(self._priv_bytes, peer_public_bytes, self._modp)
        peer = int.from_bytes(peer_public_bytes, "big")
        _validate_peer_public(peer)
        shared = pow(peer, self._priv, DH_P)
        length = (DH_P.bit_length() + 7) // 8
        raw = shared.to_bytes(length, "big")
        return raw.lstrip(b"\x00") or b"\x00"


def _validate_peer_public(peer: int) -> None:
    """Reject trivial and small-subgroup DH public values."""
    if peer <= 1 or peer >= DH_P - 1:
        raise ValueError("DH public value out of range")
    # Safe-prime subgroup check: y^q ≡ 1 (mod P) for q = (P-1)/2.
    if pow(peer, (DH_P - 1) // 2, DH_P) != 1:
        raise ValueError("DH public value not in prime-order subgroup")


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
