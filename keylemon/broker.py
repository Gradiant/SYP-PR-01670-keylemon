"""Attestation broker orchestration."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from keylemon.certificates import CertificateAuthority
from keylemon.keylime_client import KeylimeClient
from keylemon.models import AttestationResult, Decision, EndpointDescriptor
from keylemon.policy import AttestationPolicy, PolicyDecision, PolicyEngine
from keylemon.signing import ClaimSigner, ClaimVerifier
from keylemon.tee.base import TEEVerifier


def public_key_hash(public_key_pem: bytes) -> str:
    return hashlib.sha256(public_key_pem).hexdigest()


@dataclass(slots=True)
class Challenge:
    nonce: str
    bound_public_key_hash: str


@dataclass(slots=True)
class AttestationBroker:
    signer: ClaimSigner
    policy: AttestationPolicy
    tee_verifiers: dict[str, TEEVerifier] = field(default_factory=dict)
    keylime_client: KeylimeClient | None = None
    policy_engine: PolicyEngine = field(default_factory=PolicyEngine)
    ca: CertificateAuthority = field(default_factory=CertificateAuthority.create)
    result_validity: timedelta = timedelta(seconds=60)

    def create_challenge(self, public_key_pem: bytes) -> Challenge:
        return Challenge(nonce=secrets.token_urlsafe(32), bound_public_key_hash=public_key_hash(public_key_pem))

    def verify_tee(
        self,
        *,
        tee_type: str,
        subject: EndpointDescriptor,
        evidence: dict[str, Any],
        challenge: Challenge,
        transcript_hash: str | None = None,
    ) -> AttestationResult:
        verifier = self.tee_verifiers[tee_type]
        return verifier.verify(
            subject=subject,
            evidence=evidence,
            nonce=challenge.nonce,
            bound_public_key_hash=challenge.bound_public_key_hash,
            transcript_hash=transcript_hash,
            policy=self.policy,
            validity=self.result_validity,
        )

    def ingest_keylime(
        self,
        *,
        subject: EndpointDescriptor,
        agent_id: str,
        challenge: Challenge,
        keylime_response: dict[str, Any] | None = None,
    ) -> AttestationResult:
        if self.keylime_client is None:
            raise RuntimeError("Keylime client is not configured")
        return self.keylime_client.normalize_latest(
            subject=subject,
            agent_id=agent_id,
            policy_id=self.policy.policy_id,
            nonce=challenge.nonce,
            bound_public_key_hash=challenge.bound_public_key_hash,
            validity=self.result_validity,
            response=keylime_response,
        )

    def decide(
        self,
        *,
        local_results: list[AttestationResult],
        remote_results: list[AttestationResult],
        action: str = "connect",
    ) -> PolicyDecision:
        verifier = ClaimVerifier(self.signer.private_key.public_key())
        for result in local_results + remote_results:
            verifier.verify(result)
        return self.policy_engine.evaluate(self.policy, local_results, remote_results, action=action)

    def issue_certificate(self, *, subject_id: str, public_key, result: AttestationResult):
        if result.claims.final_authorization_decision != Decision.ALLOW:
            raise ValueError("cannot issue certificate for denied attestation result")
        return self.ca.issue_leaf(
            subject_id=subject_id,
            public_key=public_key,
            result=result,
            lifetime=min(self.result_validity, result.claims.result_expiry - result.claims.attestation_time),
        )

    def issue_certificate_from_pem(
        self,
        *,
        subject_id: str,
        result: AttestationResult,
        public_key_pem: str | None = None,
        csr_pem: str | None = None,
    ):
        if bool(public_key_pem) == bool(csr_pem):
            raise ValueError("provide exactly one of public_key_pem or csr_pem")
        if public_key_pem:
            public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
        else:
            csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))  # type: ignore[union-attr]
            if not csr.is_signature_valid:
                raise ValueError("CSR signature is invalid")
            public_key = csr.public_key()
        return self.issue_certificate(subject_id=subject_id, public_key=public_key, result=result)
