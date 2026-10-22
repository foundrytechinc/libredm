"""S2S server identity: Ed25519 signing keys, TOFU pinning, host policy.

Each server holds a long-term Ed25519 keypair. Every outbound S2S message
is signed. Inbound messages are verified against a pinned peer key (TOFU or
config-provided). Combined with the DH transport this gives authenticated
federation instead of anonymous encryption.
"""

import json
import os
import threading

from dmcd import config
from dmcd.s2s import log_message

try:
    from Crypto.PublicKey import ECC
    from Crypto.Signature import eddsa
except Exception:  # pragma: no cover - dependency is required at runtime
    ECC = None
    eddsa = None


def _signable(msg: dict) -> bytes:
    data = {k: v for k, v in msg.items() if k != "sig"}
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class S2SIdentity:
    """Local signing identity + trusted peer keys."""

    def __init__(self, key_path=None, trust_path=None):
        self._lock = threading.RLock()
        self.key_path = key_path or config.data_path(config.S2S_IDENTITY_FILE)
        self.trust_path = trust_path or config.data_path(config.S2S_TRUSTED_HOSTS_FILE)
        self._key = None
        self._pub_der_hex = None
        self._trusted = {}
        if ECC is None:
            log_message("pycryptodome ECC/Ed25519 unavailable; S2S signing disabled.")
            return
        self._load_or_create_key()
        self._load_trusted()

    # -- local key --------------------------------------------------------

    def _load_or_create_key(self):
        if os.path.exists(self.key_path):
            try:
                with open(self.key_path, "r", encoding="utf-8") as f:
                    self._key = ECC.import_key(f.read())
                if not self._key.has_private():
                    raise ValueError("identity file lacks private key")
            except Exception as e:
                log_message(f"Failed to load S2S identity {self.key_path}: {e}; generating new key.")
                self._key = None
        if self._key is None:
            self._key = ECC.generate(curve="Ed25519")
            pem = self._key.export_key(format="PEM")
            tmp = self.key_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(pem)
            os.replace(tmp, self.key_path)
            log_message(f"Generated new S2S identity key at {self.key_path} (mode 0600).")
        self._pub_der_hex = self._key.public_key().export_key(format="DER").hex()

    @property
    def enabled(self) -> bool:
        return self._key is not None

    @property
    def public_key_hex(self) -> str:
        return self._pub_der_hex or ""

    def sign(self, msg: dict) -> dict:
        """Return a copy of msg with from_key and sig added."""
        if self._key is None or eddsa is None:
            return dict(msg)
        out = dict(msg)
        out["from_key"] = self._pub_der_hex
        signer = eddsa.new(self._key, "rfc8032")
        out["sig"] = signer.sign(_signable(out)).hex()
        return out

    # -- peer trust (TOFU + explicit config) ------------------------------

    def _load_trusted(self):
        cfg_pins = getattr(config, "S2S_TRUSTED_KEYS", {}) or {}
        self._trusted = dict(cfg_pins)
        try:
            if os.path.exists(self.trust_path):
                with open(self.trust_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    for host, key in data.items():
                        if isinstance(host, str) and isinstance(key, str):
                            self._trusted.setdefault(host, key)
        except Exception as e:
            log_message(f"Failed to load S2S trusted hosts: {e}")

    def _save_trusted(self):
        try:
            tmp = self.trust_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._trusted, f, indent=2, sort_keys=True)
            os.replace(tmp, self.trust_path)
        except Exception as e:
            log_message(f"Failed to save S2S trusted hosts: {e}")

    def trusted_key_for(self, host: str):
        with self._lock:
            return self._trusted.get(host)

    def pin(self, host: str, pubkey_hex: str):
        if not host or not pubkey_hex:
            return
        with self._lock:
            existing = self._trusted.get(host)
            if existing and existing != pubkey_hex:
                return
            if not existing:
                self._trusted[host] = pubkey_hex
                self._save_trusted()

    def verify_message(self, msg: dict, from_host: str) -> bool:
        """Verify signature and pin consistency. False if missing/invalid."""
        if eddsa is None:
            return not config.S2S_REQUIRE_SIGNATURE
        if not isinstance(msg, dict):
            return False
        sig = msg.get("sig")
        from_key = msg.get("from_key")
        if not sig or not from_key:
            return False
        pinned = self.trusted_key_for(from_host) if from_host else None
        if pinned and pinned != from_key:
            log_message(f"S2S key mismatch for {from_host}; rejecting message.")
            return False
        try:
            pub = ECC.import_key(bytes.fromhex(from_key))
            verifier = eddsa.new(pub, "rfc8032")
            verifier.verify(_signable(msg), bytes.fromhex(sig))
        except Exception:
            return False
        if from_host and not pinned:
            self.pin(from_host, from_key)
        return True


def is_allowed_s2s_host(host: str) -> bool:
    """Federation policy: allowlist + reject private/reserved destinations."""
    if not host or not isinstance(host, str):
        return False
    if len(host) > 255 or any(c in host for c in " \t\r\n/\\@"):
        return False
    allow = getattr(config, "S2S_ALLOWED_HOSTS", []) or []
    if allow and host not in allow:
        return False
    if not getattr(config, "S2S_BLOCK_PRIVATE_HOSTS", True):
        return True
    try:
        import ipaddress
        import socket
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
    return True
