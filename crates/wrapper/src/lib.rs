use attestation_core::{Decision, PolicyDecision};
use thiserror::Error;

#[derive(Clone, Debug, Default)]
pub struct TrafficGate {
    allow_degraded: bool,
}

impl TrafficGate {
    pub fn new(allow_degraded: bool) -> Self {
        Self { allow_degraded }
    }

    pub fn authorize(&self, decision: &PolicyDecision) -> Result<(), WrapperError> {
        match decision.decision {
            Decision::Allow => Ok(()),
            Decision::Degraded if self.allow_degraded => Ok(()),
            Decision::Degraded => Err(WrapperError::DegradedNotAllowed(decision.reason.clone())),
            Decision::Deny => Err(WrapperError::Denied(decision.reason.clone())),
        }
    }

    pub fn forward_simulated(
        &self,
        decision: &PolicyDecision,
        payload: &[u8],
    ) -> Result<Vec<u8>, WrapperError> {
        self.authorize(decision)?;
        Ok(payload.to_vec())
    }
}

#[derive(Clone, Debug)]
pub struct TcpWrapper {
    pub listen_addr: String,
    pub target_addr: String,
}

impl TcpWrapper {
    pub async fn run(&self) -> Result<(), WrapperError> {
        tracing::info!(
            listen_addr = %self.listen_addr,
            target_addr = %self.target_addr,
            "tcp wrapper skeleton is initialized"
        );
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum WrapperError {
    #[error("traffic denied by policy: {0}")]
    Denied(String),
    #[error("traffic degraded but degraded mode is disabled: {0}")]
    DegradedNotAllowed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_before_successful_attestation() {
        let decision = PolicyDecision {
            decision: Decision::Deny,
            reason: "missing_attestation".to_owned(),
        };
        assert!(TrafficGate::default().authorize(&decision).is_err());
    }

    #[test]
    fn forwards_after_allow() {
        let decision = PolicyDecision {
            decision: Decision::Allow,
            reason: "ok".to_owned(),
        };
        let bytes = TrafficGate::default()
            .forward_simulated(&decision, b"hello")
            .unwrap();
        assert_eq!(bytes, b"hello");
    }
}
