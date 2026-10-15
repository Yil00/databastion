//! A scripted fake server for unit tests (as `connector-mysql/src/fake.rs`):
//! for each client message (packets up to `EOM`), the next scripted
//! response is sent as one `TABULAR_RESULT` message, or nothing for
//! [`SILENT`].

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::tds;

/// A scripted "response" that sends nothing.
pub(crate) const SILENT: &[u8] = b"\0silent";

/// Serves `responses` in order; returns the client's messages, each as
/// its packet type followed by its payload.
pub(crate) async fn serve(mut io: DuplexStream, responses: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut received = Vec::new();
    let mut responses = responses.into_iter();
    let mut current: Vec<u8> = Vec::new();
    loop {
        let mut header = [0u8; tds::HEADER];
        if io.read_exact(&mut header).await.is_err() {
            return received;
        }
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut body = vec![0u8; len.saturating_sub(tds::HEADER)];
        if io.read_exact(&mut body).await.is_err() {
            return received;
        }
        if current.is_empty() {
            current.push(header[0]);
        }
        current.extend_from_slice(&body);
        if header[1] & tds::STATUS_EOM == 0 {
            continue;
        }
        received.push(std::mem::take(&mut current));
        match responses.next() {
            Some(r) if r == SILENT => {}
            Some(r) => {
                let framed = tds::frame(tds::ptype::TABULAR_RESULT, &r, 4096);
                if io.write_all(&framed).await.is_err() {
                    return received;
                }
            }
            None => {}
        }
    }
}
