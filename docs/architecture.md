# Keylemon Architecture

```text
Endpoint wrapper
  |
  | 1. ephemeral public key
  v
Attestation broker
  |\
  | \ 2a. TPM/vTPM status ingestion
  |  v
  |  Keylime verifier
  |
  | 2b. TEE evidence verification
  v
TEE verifier backend
  |
  | 3. signed normalized attestation result
  v
Policy engine
  |
  | 4. allow/deny/degraded decision
  v
Short-lived certificate issuer
  |
  | 5. mTLS certificate with attestation result digest extension
  v
Endpoint wrapper
```

The broker keeps evidence semantics separated. Keylime remains authoritative for
TPM-shaped evidence, while TEE-specific backends verify TEE reports. The policy
engine only consumes signed normalized attestation results.

For the current PoC, the mock TEE backend exercises the complete broker and
wrapper path without hardware dependencies. Real TEE backends should replace
only the backend verifier and preserve the normalized claims interface.

