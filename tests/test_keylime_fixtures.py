from __future__ import annotations

import unittest
from datetime import timedelta

from keylemon.keylime_client import KeylimeClient
from keylemon.models import AttestationCapability, CompositeLevel, Decision, EndpointDescriptor, TPMType
from keylemon.signing import ClaimSigner


def subject(capability_type: str = "physical_tpm") -> EndpointDescriptor:
    return EndpointDescriptor(
        subject_id="node-1",
        subject_type="node",
        platform_id="node-1",
        capabilities=[
            AttestationCapability.from_dict(
                {
                    "type": capability_type,
                    "evidence_types": ["tpm_quote", "ima_log", "uefi_log"],
                    "trust_anchor": "ek_cert",
                    "verifier": "keylime_tpm",
                    "freshness": "nonce",
                    "session_binding": ["bound_public_key_hash"],
                    "composition_role": "sufficient",
                }
            )
        ],
    )


def latest_response(evaluation: str = "pass", evidence: list[dict] | None = None) -> dict:
    if evidence is None:
        evidence = [
            {"evidence_type": "tpm_quote", "data": {"meta": {"pcrs": {"sha256": {"0": "0x00", "10": "0x10"}}}}},
            {"evidence_type": "ima_log"},
            {"evidence_type": "uefi_log"},
        ]
    return {"data": {"attributes": {"evaluation": evaluation, "evidence": evidence}}}


class KeylimeFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = KeylimeClient("https://keylime.example", ClaimSigner.generate())

    def normalize(self, raw: dict, tpm_type: TPMType = TPMType.PHYSICAL):
        return self.client.normalize_latest(
            subject=subject("physical_tpm" if tpm_type == TPMType.PHYSICAL else "vtpm"),
            agent_id="node-1",
            policy_id="policy",
            nonce="nonce",
            bound_public_key_hash="pubhash",
            validity=timedelta(seconds=60),
            response=raw,
            tpm_type=tpm_type,
        ).claims

    def test_pull_or_push_pass_fixture_maps_to_allow(self) -> None:
        claims = self.normalize(latest_response())
        self.assertEqual(claims.final_authorization_decision, Decision.ALLOW)
        self.assertTrue(claims.pcr_policy_ok)
        self.assertTrue(claims.ima_runtime_ok)
        self.assertTrue(claims.measured_boot_ok)

    def test_failed_fixture_maps_to_deny(self) -> None:
        claims = self.normalize(latest_response(evaluation="fail"))
        self.assertEqual(claims.final_authorization_decision, Decision.DENY)
        self.assertFalse(claims.pcr_policy_ok)

    def test_missing_ima_and_measured_boot_are_visible(self) -> None:
        claims = self.normalize(
            latest_response(
                evidence=[
                    {
                        "evidence_type": "tpm_quote",
                        "data": {"meta": {"pcrs": {"sha256": {"0": "0x00"}}}},
                    }
                ]
            )
        )
        self.assertFalse(claims.ima_runtime_ok)
        self.assertFalse(claims.measured_boot_ok)

    def test_vtpm_classification_is_not_promoted_to_hardware(self) -> None:
        claims = self.normalize(latest_response(), tpm_type=TPMType.VIRTUAL)
        self.assertEqual(claims.tpm_type, TPMType.VIRTUAL)
        self.assertEqual(claims.composite_attestation_level, CompositeLevel.CSP_ASSERTED)
        self.assertIn("vtpm", claims.attestation_capabilities)


if __name__ == "__main__":
    unittest.main()

