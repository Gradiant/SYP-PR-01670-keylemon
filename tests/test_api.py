from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keylemon.broker import AttestationBroker
from keylemon.models import AttestationCapability, AttestationResult, EndpointDescriptor
from keylemon.policy import AttestationPolicy
from keylemon.server import make_server
from keylemon.signing import ClaimSigner
from keylemon.tee.mock import MockTEEVerifier, make_mock_report
from keylemon.wrapper import validate_peer_attestation_certificate


POLICY = """
policy_id: api-policy
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


def subject(subject_id: str) -> dict:
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
    ).to_dict()


def public_key_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")


class BrokerApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = ClaimSigner.generate()
        self.broker = AttestationBroker(
            signer=self.signer,
            policy=AttestationPolicy.from_yaml(POLICY),
            tee_verifiers={"mock": MockTEEVerifier(self.signer)},
            result_validity=timedelta(seconds=60),
        )
        self.server = make_server(self.broker, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_schema_endpoint(self) -> None:
        with urllib.request.urlopen(f"{self.base_url}/v1/schemas", timeout=5) as response:
            schemas = json.loads(response.read().decode("utf-8"))
        self.assertIn("certificate_request", schemas)

    def test_end_to_end_api_cert_issuance(self) -> None:
        key_pem = public_key_pem()
        challenge = self.post("/v1/challenges", {"public_key_pem": key_pem})
        result = self.post(
            "/v1/verify/tee/mock",
            {
                "subject": subject("local"),
                "challenge": challenge,
                "evidence": make_mock_report(
                    nonce=challenge["nonce"],
                    bound_public_key_hash=challenge["bound_public_key_hash"],
                ),
            },
        )
        decision = self.post("/v1/decide", {"local_results": [result], "remote_results": [result]})
        self.assertEqual(decision["decision"], "allow")
        cert_response = self.post(
            "/v1/certificates",
            {
                "subject_id": "local",
                "public_key_pem": key_pem,
                "attestation_result": result,
            },
        )
        cert = x509.load_pem_x509_certificate(cert_response["certificate_pem"].encode("utf-8"))
        self.assertTrue(validate_peer_attestation_certificate(cert.public_bytes(Encoding.PEM), AttestationResult.from_dict(result)))

    def test_bad_signature_returns_error(self) -> None:
        key_pem = public_key_pem()
        challenge = self.post("/v1/challenges", {"public_key_pem": key_pem})
        result = self.post(
            "/v1/verify/tee/mock",
            {
                "subject": subject("local"),
                "challenge": challenge,
                "evidence": make_mock_report(
                    nonce=challenge["nonce"],
                    bound_public_key_hash=challenge["bound_public_key_hash"],
                ),
            },
        )
        result["signature"] = "bad"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post("/v1/decide", {"local_results": [result], "remote_results": [result]})
        self.assertEqual(ctx.exception.code, 400)

    def test_expired_result_denies(self) -> None:
        expired_broker = AttestationBroker(
            signer=self.signer,
            policy=AttestationPolicy.from_yaml(POLICY),
            tee_verifiers={"mock": MockTEEVerifier(self.signer)},
            result_validity=timedelta(seconds=-1),
        )
        challenge = expired_broker.create_challenge(public_key_pem().encode("utf-8"))
        result = expired_broker.verify_tee(
            tee_type="mock",
            subject=EndpointDescriptor.from_dict(subject("expired")),
            evidence=make_mock_report(nonce=challenge.nonce, bound_public_key_hash=challenge.bound_public_key_hash),
            challenge=challenge,
        )
        decision = self.broker.decide(local_results=[result], remote_results=[result])
        self.assertEqual(decision.decision, "deny")

    def test_malformed_evidence_returns_denied_result(self) -> None:
        key_pem = public_key_pem()
        challenge = self.post("/v1/challenges", {"public_key_pem": key_pem})
        result = self.post(
            "/v1/verify/tee/mock",
            {
                "subject": subject("local"),
                "challenge": challenge,
                "evidence": {"report_data": "not-bound", "debug_disabled": True},
            },
        )
        self.assertEqual(result["claims"]["final_authorization_decision"], "deny")


if __name__ == "__main__":
    unittest.main()
