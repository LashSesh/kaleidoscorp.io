//! Shared test fixtures for the privileged transport. Compiled only under
//! `cfg(test)`; nothing here ships.

use crate::framing::{FrameTransport, TransportError};

/// A scripted in-memory transport.
///
/// Reads from a queued byte stream, records everything written, and can be told
/// to dribble bytes, time out, or fail. It records how large a single read
/// request was, which is how the pre-auth allocation bound is asserted rather
/// than asserted about.
#[derive(Default)]
pub(crate) struct FakeTransport {
    pub inbound: Vec<u8>,
    pub read_cursor: usize,
    pub written: Vec<u8>,
    /// Max bytes returned by a single `read`, to exercise short reads.
    pub read_chunk: Option<usize>,
    /// If set, `read` fails with this once the inbound stream is exhausted,
    /// instead of reporting a clean close.
    pub exhausted_error: Option<TransportError>,
    /// If set, `write_all` fails with this.
    pub write_error: Option<TransportError>,
    pub reads: usize,
    pub peak_read_request: usize,
}

impl FakeTransport {
    pub fn with_inbound(bytes: Vec<u8>) -> Self {
        FakeTransport {
            inbound: bytes,
            ..FakeTransport::default()
        }
    }

    /// Split the recorded outbound bytes back into frame bodies, so a test can
    /// assert on what the server actually said.
    pub fn written_frames(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at + 4 <= self.written.len() {
            let len = u32::from_be_bytes([
                self.written[at],
                self.written[at + 1],
                self.written[at + 2],
                self.written[at + 3],
            ]) as usize;
            at += 4;
            if at + len > self.written.len() {
                break;
            }
            out.push(self.written[at..at + len].to_vec());
            at += len;
        }
        out
    }
}

impl FrameTransport for FakeTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.reads += 1;
        self.peak_read_request = self.peak_read_request.max(buf.len());
        let remaining = self.inbound.len() - self.read_cursor;
        if remaining == 0 {
            return match self.exhausted_error.clone() {
                Some(e) => Err(e),
                None => Ok(0),
            };
        }
        let n = remaining
            .min(buf.len())
            .min(self.read_chunk.unwrap_or(usize::MAX));
        buf[..n].copy_from_slice(&self.inbound[self.read_cursor..self.read_cursor + n]);
        self.read_cursor += n;
        Ok(n)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if let Some(e) = self.write_error.clone() {
            return Err(e);
        }
        self.written.extend_from_slice(bytes);
        Ok(())
    }
}

/// Frame `body` with the 4-byte big-endian length prefix.
pub(crate) fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// Encode `value` to strict CBOR and frame it.
pub(crate) fn framed_value<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut body = Vec::new();
    ciborium::ser::into_writer(value, &mut body).expect("encode fixture");
    framed(&body)
}
