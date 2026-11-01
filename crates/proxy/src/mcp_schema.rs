//! The only adapter from validated JSON-RPC envelopes to rmcp message schemas.
//! Transport framing, session state, policy decisions and execution live elsewhere.
use crate::{Direction, Error};
use serde_json::Value;

// The SDK supports custom messages for extensibility. They are not authorization:
// reject them here even when deserialization succeeds. Never include payloads in errors.
pub(crate) fn validate(value: &Value, direction: Direction) -> Result<(), Error> {
    match direction {
        Direction::Client => {
            use rmcp::model::{
                ClientJsonRpcMessage, ClientNotification, ClientRequest, JsonRpcMessage,
            };
            let typed: ClientJsonRpcMessage =
                serde_json::from_value(value.clone()).map_err(|_| Error::InvalidMessage)?;
            match typed {
                JsonRpcMessage::Request(r)
                    if matches!(r.request, ClientRequest::CustomRequest(_)) =>
                {
                    return Err(Error::InvalidMessage);
                }
                JsonRpcMessage::Notification(n)
                    if matches!(n.notification, ClientNotification::CustomNotification(_)) =>
                {
                    return Err(Error::InvalidMessage);
                }
                _ => {}
            }
        }
        Direction::Server => {
            use rmcp::model::{
                JsonRpcMessage, ServerJsonRpcMessage, ServerNotification, ServerRequest,
            };
            let typed: ServerJsonRpcMessage =
                serde_json::from_value(value.clone()).map_err(|_| Error::InvalidMessage)?;
            match typed {
                JsonRpcMessage::Request(r)
                    if matches!(r.request, ServerRequest::CustomRequest(_)) =>
                {
                    return Err(Error::InvalidMessage);
                }
                JsonRpcMessage::Notification(n)
                    if matches!(n.notification, ServerNotification::CustomNotification(_)) =>
                {
                    return Err(Error::InvalidMessage);
                }
                _ => {}
            }
        }
    }
    Ok(())
}
