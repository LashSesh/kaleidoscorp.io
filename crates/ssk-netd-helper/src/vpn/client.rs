use super::{
    protocol::{MAX_FRAME, PROTOCOL_VERSION},
    Command, Request, Response,
};
use crate::{
    framing::{read_frame, write_frame, MAX_HANDSHAKE_FRAME},
    handshake::PRIV_HANDSHAKE_MAGIC,
    CapabilityToken, ClientError, ClientHello, FrameTransport, IdempotencyKey, LeaseKind, Nonce,
    ServerHandshake,
};

pub struct Client<T> {
    transport: T,
    token: CapabilityToken,
}
pub fn hello() -> ClientHello {
    ClientHello {
        min_protocol_version: PROTOCOL_VERSION,
        max_protocol_version: PROTOCOL_VERSION,
        ..ClientHello::new(LeaseKind::Session)
    }
}
impl<T: FrameTransport> Client<T> {
    pub fn connect(mut transport: T) -> Result<Self, ClientError> {
        write_frame(&mut transport, &hello(), MAX_HANDSHAKE_FRAME)?;
        let answer: ServerHandshake = read_frame(&mut transport, MAX_HANDSHAKE_FRAME)?;
        let hello = match answer {
            ServerHandshake::Accepted(hello) => hello,
            ServerHandshake::Rejected(reason) => return Err(ClientError::Refused(reason)),
        };
        if hello.magic != PRIV_HANDSHAKE_MAGIC || hello.protocol_version != PROTOCOL_VERSION {
            return Err(ClientError::Protocol(
                "VPN protocol mismatch; no legacy fallback".into(),
            ));
        }
        Ok(Self {
            transport,
            token: hello.session_token,
        })
    }
    pub fn send(
        &mut self,
        command: Command,
        expected_revision: u64,
        operation: IdempotencyKey,
        nonce: Nonce,
    ) -> Result<Response, ClientError> {
        let request = Request {
            session_token: self.token,
            nonce,
            idempotency_key: operation,
            expected_revision,
            command,
        };
        write_frame(&mut self.transport, &request, MAX_FRAME)?;
        Ok(read_frame(&mut self.transport, MAX_FRAME)?)
    }
}
