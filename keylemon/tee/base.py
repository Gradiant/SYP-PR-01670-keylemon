"""TEE verifier abstraction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from keylemon.models import AttestationCapability, AttestationResult, EndpointDescriptor
from keylemon.policy import AttestationPolicy


@dataclass(slots=True)
class EvidenceDescriptor:
    evidence_type: str
    media_type: str
    supports_nonce: bool
    supports_report_data: bool
    meta: dict[str, Any]


class TEEVerifier(ABC):
    verifier_id: str

    @abstractmethod
    def get_capabilities(self) -> list[EvidenceDescriptor]:
        raise NotImplementedError

    @abstractmethod
    def verify(
        self,
        *,
        subject: EndpointDescriptor,
        evidence: dict[str, Any],
        nonce: str,
        bound_public_key_hash: str,
        transcript_hash: str | None,
        policy: AttestationPolicy,
        validity: timedelta,
    ) -> AttestationResult:
        raise NotImplementedError

    @staticmethod
    def capability(tee_type: str, verifier: str) -> AttestationCapability:
        return AttestationCapability.from_dict(
            {
                "type": "tee",
                "evidence_types": [f"{tee_type}_report"],
                "trust_anchor": "tee_vendor_chain",
                "verifier": verifier,
                "freshness": "nonce",
                "session_binding": ["bound_public_key_hash"],
                "composition_role": "sufficient",
            }
        )

