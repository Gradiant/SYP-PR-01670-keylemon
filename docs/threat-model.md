# Threat Model

This PoC covers replay, stale evidence, session binding mismatch, TEE debug mode, bad TEE measurement, TPM PCR mismatch, IMA failure, and missing capability policy failures at the mock level.

Out of scope for this migration:

- Real TPM quote signature validation.
- Real EK/AK enrollment.
- Real UEFI measured boot log parsing.
- Real Linux IMA log parsing.
- Real AMD SEV-SNP, Intel TDX, SGX, or ARM CCA collateral validation.
- Protecting plaintext after a non-TEE wrapper is compromised.

Residual risks remain until real verifier backends replace mocks. The broker and wrapper must fail closed for production policies when verifiers or revocation channels are unavailable.

