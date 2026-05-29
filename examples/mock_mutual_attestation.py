"""Run a complete in-process mock mutual-attestation flow."""

from __future__ import annotations

from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keylemon.broker import AttestationBroker
from keylemon.models import AttestationCapability, EndpointDescriptor
from keylemon.policy import AttestationPolicy
from keylemon.signing import ClaimSigner
from keylemon.tee.mock import MockTEEVerifier, make_mock_report
from keylemon.wrapper import validate_peer_attestation_certificate

POLICY = """
policy_id: demo-mutual
defaults:
  max_evidence_age_seconds: 60
  require_session_binding: true
local_endpoint:
  require_any: [tee]
remote_endpoint:
  require_any: [tee]
  tee:
    permitted_types: [mock]
    debug_disabled: true
    acceptable_tcb_status: [up_to_date]
mutual:
  both_sides_attested: true
  bind_to_current_session: true
"""


def endpoint(subject_id: str) -> EndpointDescriptor:
    return EndpointDescriptor(
        subject_id=subject_id,
        subject_type="workload",
        platform_id=subject_id,
        capabilities=[
            AttestationCapability.from_dict(
                {
                    "type": "tee",
                    "evidence_types": ["mock_tee_report"],
                    "trust_anchor": "tee_vendor_chain",
                    "verifier": "tee_mock",
                    "freshness": "nonce",
                    "session_binding": ["bound_public_key_hash"],
                    "composition_role": "sufficient",
                }
            )
        ],
    )


def public_key_pem(key) -> bytes:
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def main() -> None:
    signer = ClaimSigner.generate()
    policy = AttestationPolicy.from_yaml(POLICY)
    broker = AttestationBroker(
        signer=signer,
        policy=policy,
        tee_verifiers={"mock": MockTEEVerifier(signer)},
        result_validity=timedelta(seconds=60),
    )

    local_key = ec.generate_private_key(ec.SECP256R1())
    remote_key = ec.generate_private_key(ec.SECP256R1())
    local_challenge = broker.create_challenge(public_key_pem(local_key))
    remote_challenge = broker.create_challenge(public_key_pem(remote_key))

    local_result = broker.verify_tee(
        tee_type="mock",
        subject=endpoint("local-workload"),
        evidence=make_mock_report(
            nonce=local_challenge.nonce,
            bound_public_key_hash=local_challenge.bound_public_key_hash,
        ),
        challenge=local_challenge,
    )
    remote_result = broker.verify_tee(
        tee_type="mock",
        subject=endpoint("remote-workload"),
        evidence=make_mock_report(
            nonce=remote_challenge.nonce,
            bound_public_key_hash=remote_challenge.bound_public_key_hash,
        ),
        challenge=remote_challenge,
    )

    decision = broker.decide(local_results=[local_result], remote_results=[remote_result])
    local_cert = broker.issue_certificate(subject_id="local-workload", public_key=local_key.public_key(), result=local_result)

    print(f"decision={decision.decision.value}")
    print(f"reasons={'; '.join(decision.reasons)}")
    print(f"local_cert_valid={validate_peer_attestation_certificate(local_cert.public_bytes(Encoding.PEM), local_result)}")


if __name__ == "__main__":
    main()

