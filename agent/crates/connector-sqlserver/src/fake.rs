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

/// A CA certificate unrelated to the dev server's (tests only; its key was
/// discarded when it was made): the dev server's certificate must not
/// verify against it. Kept in the source because `*.pem` files are ignored
/// by the repository.
pub(crate) const OTHER_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIDXTCCAkWgAwIBAgIUXCL7KnoVVuBzlAwCUg83TzsMO1owDQYJKoZIhvcNAQEL\n\
BQAwNTEzMDEGA1UEAwwqRGF0YUJhc3Rpb24gdGVzdCBDQSAodW5yZWxhdGVkLCBz\n\
cWxzZXJ2ZXIpMCAXDTI2MTAxNTA4MzAwNloYDzIxMjYwOTIxMDgzMDA2WjA1MTMw\n\
MQYDVQQDDCpEYXRhQmFzdGlvbiB0ZXN0IENBICh1bnJlbGF0ZWQsIHNxbHNlcnZl\n\
cikwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCjUmiP1Vs1l15gekj\n\
K5WDMzgrALjv9Ymo7chSYxOdzyHTxR0Nz9fTkH3VY9tnd1SU4JP7YzTWUzzBQMdV\n\
fabRPWjTuof02ZbPg/m/JSE1lo4ll8BJ/RuXBqZxSxvieRG8XRi0fBFgK9nYb1E6\n\
iKBj8zj3uv+DYBl0uh7X4fH28Dmn7sMNofjT/AjaBGIq8yexoS/1khezJk6ZgquM\n\
f1I3ilazwodn04DGwtm3WhNYy+1MUkIpT4RSG8Fh8fbpGN0Dciwy60gpfCc08uhh\n\
x6/W3mJuMc0Wg5BveA7s/9IqfO10SGDj07qb6LJEgWdhOQvdvCCewUJNZCttNuxc\n\
C7XHAgMBAAGjYzBhMB0GA1UdDgQWBBTsf3Lnjy1YVzwxjgLXg5OYTrM5RjAfBgNV\n\
HSMEGDAWgBTsf3Lnjy1YVzwxjgLXg5OYTrM5RjAPBgNVHRMBAf8EBTADAQH/MA4G\n\
A1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAe1zUpbDDs+5neArw8Byi\n\
5uCf2ChTF3pJfMtrqXMvXoyHU2MvCnVqCQb/qn89KBHmSVcj+FPDvnZ/lt7oKNyI\n\
so4/Ynegq05QsyrfqGg3ZT0e406p3z0c2Vf+SpK1ANiHmlG6ykMxYp1gXqnTb/zb\n\
SQW8kZ/DVHSqGx5QwETQsLgFiICq0WOW1ax+tgbB2euaP4Ei6noFVBBdPhyChAkm\n\
PhtdK1FKrAiWAmjC9vj43V8No5k0X+TcA0ptT3xaYAucNhFKMj5ohe2980XoydM6\n\
1JwKAop6kKY6iuupQpUm4MsBwXXSk6f4FcaQHDk4gqqLTE/LbPSZe7GKtggO2Z7y\n\
rQ==\n\
-----END CERTIFICATE-----\n";

/// Writes [`OTHER_CA_PEM`] to a file of its own in the temporary
/// directory; its path.
pub(crate) fn other_ca_file() -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "databastion-sqlserver-other-ca-{}-{}.pem",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, OTHER_CA_PEM).expect("other CA written");
    path
}
