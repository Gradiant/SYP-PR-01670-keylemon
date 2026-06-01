# AGENTS.md

Guidance for coding agents working in this repository.

## Project State

Keylemon is a Rust-first proof of concept for flexible platform attestation.

The Rust implementation is demo-grade. It models TPM and TEE semantics separately, composes verifier outputs through policy, and binds decisions to session material using short-lived signed tokens. It does not yet perform real Keylime ingestion, real TPM quote validation, real TEE collateral validation, mTLS, renewal, or revocation handling.

## Repository Map

- `Cargo.toml`: root package plus workspace definition.
- `crates/attestation-core`: domain models, normalized claims, verifier trait, mock TPM and mock TEE verifiers.
- `crates/policy-engine`: YAML policy model and evaluator.
- `crates/session-binding`: nonce generation, ephemeral Ed25519 keys, public-key hashes, transcript hashes, signed tokens.
- `crates/attestation-broker`: broker API and axum HTTP routes.
- `crates/wrapper`: traffic gate and TCP wrapper skeleton.
- `src/scenarios.rs`: deterministic scenario runner used by examples and smoke tests.
- `examples/`: runnable scenario binaries.
- `configs/`: demo policies and endpoint descriptors.
- `docs/`: architecture, demo, threat model, and future backend notes.
- `scripts/`: local validation, demo, and clean commands.
- `tests/`: Rust integration/smoke tests.

## Required Workflow

Use Cargo as the primary workflow. The canonical validation command is:

```bash
scripts/test.sh
```

It runs:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run demos with:

```bash
scripts/demo.sh
```

Expected demo decisions include allow, deny for IMA/debug/measurement/replay/session-binding failures, and degraded mode for the degraded policy scenario.

## Engineering Guardrails

- Keep TPM and TEE evidence semantics separate. Do not collapse them into a generic trusted flag.
- Preserve capability-driven behavior. Do not hard-code client/server roles into policy, verifier, broker, or wrapper logic.
- Treat mock verifiers as demo-only. Do not present them as security-equivalent to real TPM or TEE verification.
- Keep policy decisions explicit: `allow`, `deny`, or `degraded`.
- Keep session binding explicit through nonce and public-key hash fields.
- Prefer small, typed APIs over stringly typed ad hoc maps.
- Use `thiserror` for library errors and `anyhow` for examples or binaries.
- Keep public examples deterministic and assert their behavior in tests when possible.
- Update docs when behavior, commands, policies, or security scope changes.

## Common Tasks

### Add a new mock evidence failure

1. Add typed fields or enum values in `crates/attestation-core/src/model.rs`.
2. Add verifier behavior in `crates/attestation-core/src/mock.rs`.
3. Add policy handling if the failure should be policy-visible.
4. Add a scenario in `src/scenarios.rs` and `examples/`.
5. Add smoke coverage in `tests/scenario_smoke.rs`.
6. Run `scripts/test.sh` and `scripts/demo.sh`.

### Add a new policy condition

1. Extend the policy structs in `crates/policy-engine/src/lib.rs`.
2. Add YAML examples under `configs/policies/`.
3. Add evaluator tests.
4. Update `docs/demo.md` or `docs/architecture.md` if user-visible.

### Add a real backend

Do not wire a real backend directly into the mock path. Add a separate verifier implementation that satisfies `EvidenceVerifier`, keep vendor-specific raw details isolated, and map only stable claims into `NormalizedClaims`. Update `docs/future-real-backends.md` with trust anchors, freshness, collateral, and operational assumptions.

## Current Validation Baseline

As of the Rust migration, these commands pass:

```bash
scripts/test.sh
scripts/demo.sh
```
