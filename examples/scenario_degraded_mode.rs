use anyhow::Result;
use keylemon::scenarios::{ScenarioKind, run_scenario};

fn main() -> Result<()> {
    println!("{}", run_scenario(ScenarioKind::DegradedMode)?);
    Ok(())
}
