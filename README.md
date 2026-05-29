# Keylemon

Keylemon is a proof-of-concept hybrid attestation broker for Keylime deployments.
It keeps Keylime as the TPM/vTPM verifier of record, adds technology-specific
TEE verifier interfaces, normalizes verifier output into signed claims, evaluates
directional policies, and issues short-lived credentials for wrapper-managed
mTLS sessions.

This repository started empty, so the implementation is an external broker and
wrapper scaffold rather than a patch to upstream Keylime.

## Implemented PoC Pieces

- Normalized capability, endpoint, claim, and attestation result models.
- Ed25519 signatures over canonical attestation result documents.
- Declarative YAML policy evaluator with local/remote/mutual sections.
- Mock TEE verifier for CI and local development.
- Keylime latest-attestation ingestion adapter for TPM/vTPM claim mapping.
- Short-lived X.509 certificate issuer with an attestation result digest
  extension.
- Minimal stdlib HTTP broker API.
- TCP wrapper skeleton for application-transparent mTLS tunnels.
- Public JSON schema descriptions for the broker API.
- Mock mutual-attestation and echo-gate demos.

## Run Tests

```bash
uv sync --dev
uv run python -m unittest discover -s tests
uv run pytest
uv run ruff check .
```

## Run Broker

```bash
uv run keylemon-broker --policy examples/policy.yaml --host 127.0.0.1 --port 8765
```

## API Sketch

- `POST /v1/challenges`: input `{"public_key_pem": "..."}`.
- `POST /v1/verify/tee/mock`: verifies mock TEE evidence and returns a signed result.
- `POST /v1/decide`: evaluates local and remote signed attestation results.
- `POST /v1/certificates`: issues a short-lived PEM certificate for an allowed attestation result.
- `GET /v1/schemas`: returns JSON schema fragments for the broker request/response shapes.

## Run Demos

```bash
uv run python examples/mock_mutual_attestation.py
uv run python examples/echo_demo.py
```

The mock TEE backend is not a security mechanism. It exists to validate broker,
policy, claim-signing, and wrapper flows before adding real TEE collateral
verification.

See [docs/architecture.md](docs/architecture.md) for the broker, wrapper,
Keylime, and TEE verifier sequence.
