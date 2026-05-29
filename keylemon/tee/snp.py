"""AMD SEV-SNP adapter placeholder.

This module defines the broker-facing shape for a future real SEV-SNP verifier.
It deliberately does not claim production SNP verification yet.  The upstream
Keylime helper at ``keylime/tee/snp.py`` can be adapted here once the runtime
environment supplies SNP report bytes and AMD collateral handling policy.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from keylemon.models import EndpointDescriptor
from keylemon.policy import AttestationPolicy
from keylemon.tee.base import EvidenceDescriptor, TEEVerifier


class SevSnpVerifier(TEEVerifier):
    verifier_id = "tee_sev_snp"

    def get_capabilities(self) -> list[EvidenceDescriptor]:
        return [
            EvidenceDescriptor(
                evidence_type="sev_snp_report",
                media_type="application/octet-stream",
                supports_nonce=True,
                supports_report_data=True,
                meta={"tee_type": "sev_snp", "status": "adapter_not_implemented"},
            )
        ]

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
    ):
        raise NotImplementedError("real AMD SEV-SNP verification is planned but not implemented in this PoC")

