use keylemon::scenarios::{ScenarioKind, run_scenario};

#[test]
fn allowed_scenario_allows_traffic() {
    let output = run_scenario(ScenarioKind::Allowed).unwrap();
    assert!(output.starts_with("decision=allow"));
}

#[test]
fn ima_failure_scenario_denies_traffic() {
    let output = run_scenario(ScenarioKind::ImaFail).unwrap();
    assert!(output.contains("decision=deny"));
    assert!(output.contains("ima runtime policy failed"));
}

#[test]
fn tee_debug_scenario_denies_traffic() {
    let output = run_scenario(ScenarioKind::TeeDebug).unwrap();
    assert!(output.contains("decision=deny"));
    assert!(output.contains("tee debug mode enabled"));
}

#[test]
fn bad_measurement_scenario_denies_traffic() {
    let output = run_scenario(ScenarioKind::BadMeasurement).unwrap();
    assert!(output.contains("decision=deny"));
    assert!(output.contains("tee measurement denied"));
}

#[test]
fn replay_scenario_denies_traffic() {
    let output = run_scenario(ScenarioKind::Replay).unwrap();
    assert!(output.contains("decision=deny"));
    assert!(output.contains("evidence expired"));
}

#[test]
fn session_binding_failure_scenario_denies_traffic() {
    let output = run_scenario(ScenarioKind::SessionBindingFail).unwrap();
    assert!(output.contains("decision=deny"));
    assert!(output.contains("public key binding mismatch"));
}

#[test]
fn degraded_mode_scenario_degrades_traffic() {
    let output = run_scenario(ScenarioKind::DegradedMode).unwrap();
    assert!(output.starts_with("decision=degraded"));
}
