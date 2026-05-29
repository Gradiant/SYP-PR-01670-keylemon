"""JSON schema fragments for the broker HTTP API.

The project intentionally avoids a runtime JSON-schema dependency for the PoC.
These schemas document the public wire shape and are exposed by ``GET
/v1/schemas`` for clients and tests.
"""

from __future__ import annotations

from typing import Any


SCHEMAS: dict[str, dict[str, Any]] = {
    "challenge_request": {
        "type": "object",
        "required": ["public_key_pem"],
        "properties": {"public_key_pem": {"type": "string"}},
        "additionalProperties": False,
    },
    "challenge_response": {
        "type": "object",
        "required": ["nonce", "bound_public_key_hash"],
        "properties": {
            "nonce": {"type": "string"},
            "bound_public_key_hash": {"type": "string"},
        },
    },
    "mock_tee_verify_request": {
        "type": "object",
        "required": ["subject", "challenge", "evidence"],
        "properties": {
            "subject": {"type": "object"},
            "challenge": {"$ref": "#/challenge_response"},
            "evidence": {"type": "object"},
            "transcript_hash": {"type": ["string", "null"]},
        },
    },
    "attestation_result": {
        "type": "object",
        "required": ["claims", "signature", "signing_alg", "key_id"],
        "properties": {
            "claims": {"type": "object"},
            "signature": {"type": "string"},
            "signing_alg": {"type": "string"},
            "key_id": {"type": "string"},
        },
    },
    "decision_request": {
        "type": "object",
        "required": ["local_results", "remote_results"],
        "properties": {
            "local_results": {"type": "array", "items": {"$ref": "#/attestation_result"}},
            "remote_results": {"type": "array", "items": {"$ref": "#/attestation_result"}},
            "action": {"type": "string"},
        },
    },
    "decision_response": {
        "type": "object",
        "required": ["decision", "reasons"],
        "properties": {
            "decision": {"enum": ["allow", "deny", "degraded"]},
            "reasons": {"type": "array", "items": {"type": "string"}},
        },
    },
    "certificate_request": {
        "type": "object",
        "required": ["subject_id", "attestation_result"],
        "properties": {
            "subject_id": {"type": "string"},
            "public_key_pem": {"type": "string"},
            "csr_pem": {"type": "string"},
            "attestation_result": {"$ref": "#/attestation_result"},
        },
        "oneOf": [{"required": ["public_key_pem"]}, {"required": ["csr_pem"]}],
    },
    "certificate_response": {
        "type": "object",
        "required": ["certificate_pem", "ca_certificate_pem", "attestation_digest_sha256"],
        "properties": {
            "certificate_pem": {"type": "string"},
            "ca_certificate_pem": {"type": "string"},
            "attestation_digest_sha256": {"type": "string"},
        },
    },
}

