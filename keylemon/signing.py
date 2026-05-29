"""Canonical signing helpers for attestation results."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from keylemon.models import AttestationResult, NormalizedClaims


def canonical_json(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


@dataclass(slots=True)
class ClaimSigner:
    private_key: Ed25519PrivateKey
    key_id: str = "default"

    @classmethod
    def generate(cls, key_id: str = "default") -> "ClaimSigner":
        return cls(Ed25519PrivateKey.generate(), key_id)

    @classmethod
    def from_private_pem(cls, data: bytes, key_id: str = "default") -> "ClaimSigner":
        key = load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("attestation result signing key must be Ed25519")
        return cls(key, key_id)

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def sign(self, claims: NormalizedClaims) -> AttestationResult:
        claims.key_id = self.key_id
        payload = canonical_json(claims.to_dict())
        return AttestationResult(
            claims=claims,
            signature=b64url(self.private_key.sign(payload)),
            signing_alg="ed25519",
            key_id=self.key_id,
        )


@dataclass(slots=True)
class ClaimVerifier:
    public_key: Ed25519PublicKey

    @classmethod
    def from_public_pem(cls, data: bytes) -> "ClaimVerifier":
        key = load_pem_public_key(data)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("attestation result verification key must be Ed25519")
        return cls(key)

    def verify(self, result: AttestationResult) -> bool:
        self.public_key.verify(b64url_decode(result.signature), canonical_json(result.claims.to_dict()))
        return True

