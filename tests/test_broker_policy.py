from __future__ import annotations

import unittest
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keylemon.broker import AttestationBroker
from keylemon.models import AttestationCapability, EndpointDescriptor
from keylemon.policy import AttestationPolicy
from keylemon.signing import ClaimSigner, ClaimVerifier
from keylemon.tee.mock import MockTEEVerifier, make_mock_report


POLICY = """
policy_id: test-policy
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


def public_key_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def subject(subject_id: str) -> EndpointDescriptor:
    return EndpointDescriptor(
        subject_id=subject_id,
        subject_type="workload",
        platform_id=subject_id,
        capabilities=[AttestationCapability.from_dict({
            "type": "tee",
            "evidence_types": ["mock_tee_report"],
            "trust_anchor": "tee_vendor_chain",
            "verifier": "tee_mock",
            "freshness": "nonce",
            "session_binding": ["bound_public_key_hash"],
            "composition_role": "sufficient",
        })],
    )


class BrokerPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = ClaimSigner.generate()
        self.broker = AttestationBroker(
            signer=self.signer,
            policy=AttestationPolicy.from_yaml(POLICY),
            tee_verifiers={"mock": MockTEEVerifier(self.signer)},
            result_validity=timedelta(seconds=60),
        )

    def test_mock_tee_result_is_signed_and_policy_allows_mutual(self) -> None:
        local_challenge = self.broker.create_challenge(public_key_pem())
        remote_challenge = self.broker.create_challenge(public_key_pem())

        local = self.broker.verify_tee(
            tee_type="mock",
            subject=subject("local"),
            evidence=make_mock_report(
                nonce=local_challenge.nonce,
                bound_public_key_hash=local_challenge.bound_public_key_hash,
            ),
            challenge=local_challenge,
        )
        remote = self.broker.verify_tee(
            tee_type="mock",
            subject=subject("remote"),
            evidence=make_mock_report(
                nonce=remote_challenge.nonce,
                bound_public_key_hash=remote_challenge.bound_public_key_hash,
            ),
            challenge=remote_challenge,
        )

        self.assertTrue(ClaimVerifier(self.signer.private_key.public_key()).verify(local))
        decision = self.broker.decide(local_results=[local], remote_results=[remote])
        self.assertEqual(decision.decision, "allow")

    def test_report_data_mismatch_denies(self) -> None:
        challenge = self.broker.create_challenge(public_key_pem())
        evidence = make_mock_report(nonce=challenge.nonce, bound_public_key_hash=challenge.bound_public_key_hash)
        evidence["report_data"] = "wrong"
        result = self.broker.verify_tee(
            tee_type="mock",
            subject=subject("local"),
            evidence=evidence,
            challenge=challenge,
        )
        self.assertEqual(result.claims.final_authorization_decision, "deny")


if __name__ == "__main__":
    unittest.main()

