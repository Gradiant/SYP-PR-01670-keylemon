# Future Real Backends

Keylime integration should remain external-first:

1. Consume latest attestation state from a Keylime verifier.
2. Map TPM, PCR, measured boot, and IMA results into `NormalizedClaims`.
3. Preserve Keylime as the TPM verifier of record.
4. Add minimal upstream Keylime API changes only after fixture-based ingestion proves which fields are missing.

TEE backend work should add separate verifier implementations for:

- AMD SEV-SNP: validate report signatures, VCEK chain, TCB status, debug indicators, and report-data binding.
- Intel TDX: validate quote collateral, measurements, TCB status, and report-data binding.
- Intel SGX: validate quote collateral, enclave measurements, and debug mode for enclave workloads.
- ARM CCA: add only after stable evidence and collateral handling are selected.

vTPM trust should be classified as virtual unless policy can bind the vTPM AK to a TEE instance, hardware root, or CSP assertion.

