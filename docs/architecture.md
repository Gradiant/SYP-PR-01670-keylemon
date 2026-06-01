# Architecture

Keylemon uses a hybrid, capability-driven attestation model:

1. Endpoints produce typed evidence such as mock TPM evidence, mock TEE evidence, or no-hardware evidence.
2. Verifiers evaluate technology-specific evidence and produce normalized claims. TPM and TEE semantics are intentionally separate.
3. The broker composes local and remote attestation results through a policy.
4. Session binding ties the result to a nonce and ephemeral public-key hash.
5. The wrapper traffic gate forwards application payloads only after policy allows or explicitly permits degraded mode.

The broker HTTP surface is:

- `POST /v1/challenges`
- `POST /v1/evidence`
- `POST /v1/decide`
- `POST /v1/tokens`
- `GET /v1/schemas`

The first implementation uses library calls in examples for deterministic smoke tests. The axum router is available for integration tests and future services.

