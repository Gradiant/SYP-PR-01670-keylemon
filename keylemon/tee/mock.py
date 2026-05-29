"""Mock TEE backend for development and CI.

The mock backend is intentionally deterministic and policy-checkable.  It is not
a security mechanism; it lets the broker, wrapper, and policy paths be tested
without hardware-specific TEE collateral.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from keylemon.models import CompositeLevel, Decision, EndpointDescriptor, NormalizedClaims
from keylemon.policy import AttestationPolicy
from keylemon.signing import ClaimSigner
from keylemon.tee.base import EvidenceDescriptor, TEEVerifier


class MockTEEVerifier(TEEVerifier):
    verifier_id = "tee_mock"

    def __init__(self, signer: ClaimSigner) -> None:
        self.signer = signer

    def get_capabilities(self) -> list[EvidenceDescriptor]:
        return [
            EvidenceDescriptor(
                evidence_type="mock_tee_report",
                media_type="application/json",
                supports_nonce=True,
                supports_report_data=True,
                meta={"tee_type": "mock"},
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
        report_data = evidence.get("report_data")
        expected_report_data = hashlib.sha256(f"{nonce}:{bound_public_key_hash}".encode("utf-8")).hexdigest()
        debug_disabled = bool(evidence.get("debug_disabled", False))
        measurement = evidence.get("measurement", "")
        tcb_status = evidence.get("tcb_status", "unknown")

        claims = NormalizedClaims.minimal(
            subject=subject,
            evidence_type="mock_tee_report",
            verifier_id=self.verifier_id,
            policy_id=policy.policy_id,
            nonce=nonce,
            bound_public_key_hash=bound_public_key_hash,
            validity=validity,
        )
        claims.policy_version = policy.policy_version
        claims.session_transcript_hash = transcript_hash
        claims.tee_present = True
        claims.tee_type = "mock"
        claims.tee_vendor = "keylemon"
        claims.tee_measurement = measurement
        claims.tee_tcb_status = tcb_status
        claims.tee_debug_disabled = debug_disabled
        claims.tee_instance_id = evidence.get("instance_id")
        claims.tee_report_data_hash = report_data
        claims.composite_attestation_level = CompositeLevel.SOFTWARE
        claims.final_authorization_decision = Decision.ALLOW
        claims.raw = {"tee": {"mock": evidence}}

        if report_data != expected_report_data:
            claims.final_authorization_decision = Decision.DENY
            claims.raw["verification_error"] = "report_data does not bind nonce and public key"
        elif not debug_disabled:
            claims.final_authorization_decision = Decision.DENY
            claims.raw["verification_error"] = "mock TEE debug mode is enabled"

        return self.signer.sign(claims)


def make_mock_report(*, nonce: str, bound_public_key_hash: str, measurement: str = "mock:default") -> dict[str, Any]:
    return {
        "measurement": measurement,
        "tcb_status": "up_to_date",
        "debug_disabled": True,
        "instance_id": "mock-instance",
        "report_data": hashlib.sha256(f"{nonce}:{bound_public_key_hash}".encode("utf-8")).hexdigest(),
    }

