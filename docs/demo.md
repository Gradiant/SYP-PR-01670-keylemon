# Demo

The demos do not require Docker, Kubernetes, a TPM, a TEE, or Keylime. They use mock evidence and policy files in `configs/`.

Run:

```bash
scripts/demo.sh
```

Scenarios:

- `scenario_allowed`: physical TPM-like evidence on endpoint A and TEE-like evidence on endpoint B satisfy mutual policy.
- `scenario_ima_fail`: TPM evidence fails runtime IMA policy.
- `scenario_tee_debug`: TEE evidence has debug enabled.
- `scenario_bad_measurement`: TEE measurement is not in the allowlist.
- `scenario_replay`: TPM evidence has expired.
- `scenario_session_binding_fail`: TEE report binds to a different public-key hash.
- `scenario_degraded_mode`: unauthenticated traffic is accepted only under the degraded demo policy.

