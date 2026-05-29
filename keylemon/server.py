"""Small stdlib HTTP API for broker PoC deployments."""

from __future__ import annotations

import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives import serialization

from keylemon.broker import AttestationBroker
from keylemon.certificates import attestation_result_digest
from keylemon.models import AttestationResult, EndpointDescriptor
from keylemon.schemas import SCHEMAS


@dataclass(slots=True)
class RequestChallenge:
    nonce: str
    bound_public_key_hash: str


class BrokerRequestHandler(BaseHTTPRequestHandler):
    broker: AttestationBroker

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/v1/schemas":
            self._json(200, SCHEMAS)
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            body = self._read_json()
            if self.path == "/v1/challenges":
                public_key_pem = body["public_key_pem"].encode("utf-8")
                challenge = self.broker.create_challenge(public_key_pem)
                self._json(200, {"nonce": challenge.nonce, "bound_public_key_hash": challenge.bound_public_key_hash})
                return

            if self.path == "/v1/verify/tee/mock":
                subject = EndpointDescriptor.from_dict(body["subject"])
                challenge = body["challenge"]
                result = self.broker.verify_tee(
                    tee_type="mock",
                    subject=subject,
                    evidence=body["evidence"],
                    challenge=RequestChallenge(**challenge),
                    transcript_hash=body.get("transcript_hash"),
                )
                self._json(200, result.to_dict())
                return

            if self.path == "/v1/decide":
                local = [AttestationResult.from_dict(item) for item in body.get("local_results", [])]
                remote = [AttestationResult.from_dict(item) for item in body.get("remote_results", [])]
                decision = self.broker.decide(
                    local_results=local,
                    remote_results=remote,
                    action=body.get("action", "connect"),
                )
                self._json(200, {"decision": decision.decision.value, "reasons": decision.reasons})
                return

            if self.path == "/v1/certificates":
                result = AttestationResult.from_dict(body["attestation_result"])
                cert = self.broker.issue_certificate_from_pem(
                    subject_id=body["subject_id"],
                    result=result,
                    public_key_pem=body.get("public_key_pem"),
                    csr_pem=body.get("csr_pem"),
                )
                self._json(
                    200,
                    {
                        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                        "ca_certificate_pem": self.broker.ca.certificate_pem().decode("utf-8"),
                        "attestation_digest_sha256": attestation_result_digest(result).hex(),
                    },
                )
                return

            self._json(404, {"error": "not_found"})
        except json.JSONDecodeError as exc:
            self._json(400, {"error": "invalid_json", "detail": str(exc)})
        except Exception as exc:  # pragma: no cover - defensive API boundary
            self._json(400, {"error": type(exc).__name__, "detail": str(exc)})

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, status: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") or "{}"
        parsed = json.loads(body)
        if not isinstance(parsed, dict):
            raise ValueError("request body must be a JSON object")
        return parsed


def make_server(broker: AttestationBroker, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    handler = type("ConfiguredBrokerRequestHandler", (BrokerRequestHandler,), {"broker": broker})
    return ThreadingHTTPServer((host, port), handler)


def serve(broker: AttestationBroker, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = make_server(broker, host, port)
    server.serve_forever()
    return server
