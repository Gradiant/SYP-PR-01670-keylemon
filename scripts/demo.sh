#!/usr/bin/env bash
set -euo pipefail

cargo run --example scenario_allowed
cargo run --example scenario_ima_fail
cargo run --example scenario_tee_debug
cargo run --example scenario_bad_measurement
cargo run --example scenario_replay
cargo run --example scenario_session_binding_fail
cargo run --example scenario_degraded_mode

