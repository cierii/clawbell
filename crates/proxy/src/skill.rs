//! Exact initialize.instructions binding to the native runner's prior skill scan.
use crate::{Direction, Envelope, Error, Gate, Reason};
use clawbell_sandbox::transaction::skill::InstructionBinding;
use serde_json::Value;

/// Mandatory decorator for a scan-bound local skill session. Both the received
/// and approved instruction field must match; DLP changes cause refusal.
pub struct SkillGate<G> {
    inner: G,
    binding: InstructionBinding,
    initialize: Option<Value>,
    checked: bool,
    closed: bool,
}
impl<G: Gate> SkillGate<G> {
    /// Bind one fresh gate to a scan; this grants no policy or audit permission.
    pub fn new(inner: G, binding: InstructionBinding) -> Self {
        Self {
            inner,
            binding,
            initialize: None,
            checked: false,
            closed: false,
        }
    }
}
impl<G: Gate> Gate for SkillGate<G> {
    fn permits_remote(&self) -> bool {
        false
    }
    async fn inspect(
        &mut self,
        direction: Direction,
        message: &Envelope,
    ) -> Result<Envelope, Error> {
        if self.closed {
            return Err(Error::Denied);
        }
        if direction == Direction::Client && message.method() == Some("initialize") {
            if self.initialize.is_some() || self.checked {
                self.closed = true;
                return Err(Error::Protocol);
            }
            self.initialize = Some(message.id().cloned().ok_or(Error::Protocol)?);
        }
        if direction == Direction::Server
            && message.method().is_none()
            && self.initialize.as_ref() == message.id()
        {
            if !self.binding.matches(
                message
                    .value()
                    .pointer("/result/instructions")
                    .and_then(Value::as_str),
            ) {
                self.closed = true;
                return Err(Error::Refused(Reason::CatalogDenied));
            }
            self.checked = true;
            self.initialize = None;
        }
        let result = self.inner.inspect(direction, message).await;
        if direction == Direction::Server
            && self.checked
            && message.value().pointer("/result/instructions").is_some()
            && result.as_ref().is_ok_and(|packet| {
                !self.binding.matches(
                    packet
                        .value()
                        .pointer("/result/instructions")
                        .and_then(Value::as_str),
                )
            })
        {
            self.closed = true;
            return Err(Error::Refused(Reason::CatalogDenied));
        }
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    async fn terminated(&mut self, reason: Reason) -> Result<(), Error> {
        self.inner.terminated(reason).await
    }
    async fn finish(&mut self) -> Result<(), Error> {
        self.closed = true;
        self.inner.finish().await
    }
}
