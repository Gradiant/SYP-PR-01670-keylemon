from __future__ import annotations

import unittest
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric import ec

from keylemon.certificates import CertificateAuthority, attestation_digest_from_cert
from keylemon.models import Decision, EndpointDescriptor, NormalizedClaims
from keylemon.signing import ClaimSigner


class CertificateTests(unittest.TestCase):
    def test_attestation_digest_extension_is_present(self) -> None:
        signer = ClaimSigner.generate()
        subject = EndpointDescriptor("subject", "node", "platform", [])
        claims = NormalizedClaims.minimal(
            subject=subject,
            evidence_type="mock",
            verifier_id="mock",
            policy_id="policy",
            nonce="nonce",
            bound_public_key_hash="pubhash",
            validity=timedelta(seconds=60),
        )
        claims.final_authorization_decision = Decision.ALLOW
        result = signer.sign(claims)
        key = ec.generate_private_key(ec.SECP256R1())
        cert = CertificateAuthority.create().issue_leaf(
            subject_id="subject",
            public_key=key.public_key(),
            result=result,
            lifetime=timedelta(seconds=60),
        )
        self.assertIsNotNone(attestation_digest_from_cert(cert))


if __name__ == "__main__":
    unittest.main()
