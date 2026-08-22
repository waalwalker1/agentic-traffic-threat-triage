"""Local cryptographic identity fixture and Ed25519 signature verification."""

import base64
import hashlib
from typing import NamedTuple

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


def sign_payload(private_key_b64: str, payload: str | bytes) -> str:
    """Sign a canonical payload with Ed25519 private key."""
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
    timestamp_iso: str,
) -> str:
    """Build deterministic canonical string for signing."""
    return f"SOURCE={source_id_hash}|ROUTE={route_template}|TIME={timestamp_iso}"


def get_default_registry() -> IdentityRegistry:
    return _GLOBAL_REGISTRY
