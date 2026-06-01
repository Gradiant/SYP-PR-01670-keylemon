# Keylemon

Keylemon is a Rust-first proof of concept for capability-driven platform attestation. It models separate TPM and TEE evidence, composes verifier results through policy, and demonstrates session-bound authorization with short-lived signed tokens.

## Workspace

- `crates/attestation-core`: domain models, normalized claims, verifier trait, mock TPM and mock TEE verifiers.
- `crates/policy-engine`: YAML policy model and evaluator.
- `crates/session-binding`: nonces, ephemeral keys, transcript hashes, and signed short-lived attestation tokens.
- `crates/attestation-broker`: broker library plus axum API routes for challenges, evidence, decisions, tokens, and schema hints.
- `crates/wrapper`: deterministic traffic gate and TCP wrapper skeleton.
- `examples/`: local mock scenarios.
- `configs/`: demo policies and endpoint descriptors.

## Security Scope

This repository does not perform real TPM quote validation, real TEE collateral validation, mTLS, or Keylime verifier integration yet. The TPM and TEE verifiers are deterministic mocks for local architecture and policy tests. Real Keylime, AMD SEV-SNP, Intel TDX, SGX, and TEE-backed vTPM support are future backends documented in `docs/future-real-backends.md`.

## Build And Test

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Or run the canonical script:

```bash
scripts/test.sh
```

## Demo Scenarios

```bash
cargo run --example scenario_allowed
cargo run --example scenario_ima_fail
cargo run --example scenario_tee_debug
cargo run --example scenario_bad_measurement
cargo run --example scenario_replay
cargo run --example scenario_session_binding_fail
cargo run --example scenario_degraded_mode
```

Expected outputs are deterministic decision lines, for example:

```text
decision=allow reason=policy_satisfied
decision=deny reason=attestation verification failed: ima runtime policy failed
decision=deny reason=attestation verification failed: tee debug mode enabled
```

Run all examples:

```bash
scripts/demo.sh
```

## Local Cleanup

```bash
scripts/clean.sh
```
