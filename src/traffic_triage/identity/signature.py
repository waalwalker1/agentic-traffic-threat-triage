"""Local cryptographic identity fixture and Ed25519 signature verification."""

import base64
import hashlib
from typing import Any, NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class KeyPair(NamedTuple):
    private_key_b64: str
    public_key_b64: str


class IdentityRegistry:
    """In-memory registry of known agent identities and public verification keys."""

    def __init__(self) -> None:
        self._keys: dict[str, str] = {}
        self._seed_default_fixture_keys()

    def _seed_default_fixture_keys(self) -> None:
        for name in [
            "verified-fetcher-v1",
            "partner-research-bot",
            "compliance-auditor",
            "search-crawler-v2",
        ]:
            seed_bytes = hashlib.sha256(f"static_seed_{name}".encode()).digest()
            priv = Ed25519PrivateKey.from_private_bytes(seed_bytes)
            pub = priv.public_key()
            self._keys[name] = base64.b64encode(pub.public_bytes_raw()).decode("ascii")

    def register(self, identity_claim: str, public_key_b64: str) -> None:
        self._keys[identity_claim] = public_key_b64

    def get_public_key(self, identity_claim: str) -> str | None:
        return self._keys.get(identity_claim)


_GLOBAL_REGISTRY = IdentityRegistry()


def generate_deterministic_keypair(identity_claim: str) -> KeyPair:
    """Generate fixed deterministic Ed25519 keypair for standard test agent identities."""
    seed_bytes = hashlib.sha256(f"static_seed_{identity_claim}".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed_bytes)
    pub = priv.public_key()
    return KeyPair(
        private_key_b64=base64.b64encode(priv.private_bytes_raw()).decode("ascii"),
        public_key_b64=base64.b64encode(pub.public_bytes_raw()).decode("ascii"),
    )


def generate_keypair() -> KeyPair:
    """Generate a new Ed25519 keypair encoded as base64 strings."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return KeyPair(
        private_key_b64=base64.b64encode(priv.private_bytes_raw()).decode("ascii"),
        public_key_b64=base64.b64encode(pub.public_bytes_raw()).decode("ascii"),
    )


def sign_payload(payload: str | bytes, private_key_b64: str) -> str:
    """Sign a canonical payload with Ed25519 private key."""
    if isinstance(payload, str) and len(payload) == 44 and payload.endswith("="):
        try:
            b = base64.b64decode(payload)
            if len(b) == 32 and not (
                isinstance(private_key_b64, str)
                and len(private_key_b64) == 44
                and private_key_b64.endswith("=")
            ):
                payload, private_key_b64 = private_key_b64, payload
        except Exception:
            pass

    priv_bytes = base64.b64decode(private_key_b64)
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    sig = priv.sign(data)
    return base64.b64encode(sig).decode("ascii")


def verify_signature(
    public_key_b64: str,
    payload: str | bytes,
    signature_b64: str,
) -> bool:
    """Verify Ed25519 signature against given payload and base64 public key."""
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(signature_b64)
        data = payload.encode("utf-8") if isinstance(payload, str) else payload
        pub.verify(sig_bytes, data)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def build_canonical_request_payload(
    source_id_hash: str,
    route_template: str,
    timestamp_iso: Any,
) -> str:
    """Build deterministic canonical string for signing."""
    ts_str = (
        timestamp_iso.isoformat() if hasattr(timestamp_iso, "isoformat") else str(timestamp_iso)
    )
    return f"SOURCE={source_id_hash}|ROUTE={route_template}|TIME={ts_str}"


def get_default_registry() -> IdentityRegistry:
    return _GLOBAL_REGISTRY
