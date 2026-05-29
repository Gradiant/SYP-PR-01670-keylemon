from __future__ import annotations

import unittest
from datetime import timedelta

from keylemon.keylime_client import KeylimeClient
from keylemon.models import AttestationCapability, EndpointDescriptor
from keylemon.signing import ClaimSigner


class KeylimeClientTests(unittest.TestCase):
    def test_normalize_latest_passed_attestation(self) -> None:
        signer = ClaimSigner.generate()
        client = KeylimeClient("https://keylime.example", signer)
        subject = EndpointDescriptor(
            subject_id="node-1",
            subject_type="node",
            platform_id="node-1",
            capabilities=[AttestationCapability.from_dict({
                "type": "physical_tpm",
                "evidence_types": ["tpm_quote", "ima_log", "uefi_log"],
                "trust_anchor": "ek_cert",
                "verifier": "keylime_tpm",
                "freshness": "nonce",
                "session_binding": ["bound_public_key_hash"],
                "composition_role": "sufficient",
            })],
        )
        raw = {
            "data": {
                "attributes": {
                    "evaluation": "pass",
                    "evidence": [
                        {"evidence_type": "tpm_quote", "data": {"meta": {"pcrs": {"sha256": {"10": "0x00"}}}}},
                        {"evidence_type": "ima_log"},
                        {"evidence_type": "uefi_log"},
                    ],
                }
            }
        }

        result = client.normalize_latest(
            subject=subject,
            agent_id="node-1",
            policy_id="policy",
            nonce="nonce",
            bound_public_key_hash="pubhash",
            validity=timedelta(seconds=60),
            response=raw,
        )

        self.assertTrue(result.claims.tpm_present)
        self.assertEqual(result.claims.final_authorization_decision, "allow")
        self.assertEqual(result.claims.pcr_selection, {"sha256": {"10": "0x00"}})
        self.assertTrue(result.claims.ima_runtime_ok)
        self.assertTrue(result.claims.measured_boot_ok)


if __name__ == "__main__":
    unittest.main()

