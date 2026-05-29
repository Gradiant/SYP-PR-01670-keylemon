"""Minimal echo-gate demo for wrapper attestation decisions.

This does not open sockets.  It demonstrates the wrapper's enforcement rule:
traffic is denied before an attested certificate is available and allowed once
the certificate contains the expected attestation result digest.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.serialization import Encoding

from keylemon.models import AttestationCapability, EndpointDescriptor
from keylemon.broker import AttestationBroker
from keylemon.policy import AttestationPolicy
from keylemon.signing import ClaimSigner
from keylemon.tee.mock import MockTEEVerifier, make_mock_report
from keylemon.wrapper import validate_peer_attestation_certificate

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import PublicFormat


POLICY = """
policy_id: echo-demo
defaults:
  max_evidence_age_seconds: 60
  require_session_binding: true
local_endpoint:
  require_any: [tee]
remote_endpoint:
  require_any: [tee]
mutual:
  both_sides_attested: true
  bind_to_current_session: true
"""


def echo_gate(message: bytes, cert_pem: bytes | None, expected_result) -> bytes:
    if cert_pem is None or not validate_peer_attestation_certificate(cert_pem, expected_result):
        raise PermissionError("traffic denied before attestation")
    return message


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
    broker = AttestationBroker(
        signer=signer,
        policy=AttestationPolicy.from_yaml(POLICY),
        tee_verifiers={"mock": MockTEEVerifier(signer)},
    )
    key = ec.generate_private_key(ec.SECP256R1())
    challenge = broker.create_challenge(public_key_pem(key))
    result = broker.verify_tee(
        tee_type="mock",
        subject=endpoint("echo-client"),
        evidence=make_mock_report(nonce=challenge.nonce, bound_public_key_hash=challenge.bound_public_key_hash),
        challenge=challenge,
    )

    try:
        echo_gate(b"hello", None, result)
    except PermissionError as exc:
        print(str(exc))

    cert = broker.issue_certificate(subject_id="echo-client", public_key=key.public_key(), result=result)
    print(echo_gate(b"hello", cert.public_bytes(Encoding.PEM), result).decode("utf-8"))


if __name__ == "__main__":
    main()
