//! A stand-in server for the unit tests, on one end of socket pairs handed
//! to the next sessions of a target through `node`'s test transports: no
//! listening socket (I1, the agent's architecture test). Never compiled
//! into the agent.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// How one connection of the stand-in answers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fake {
    /// The connection id `HELLO` reports.
    pub(crate) id: i64,
    /// `run_id` of `INFO server`.
    pub(crate) run: &'static str,
    /// `role:slave` in `INFO replication` (else `role:master`).
    pub(crate) replica: bool,
    /// `ACL DRYRUN` answers with a command-level denial (else `OK`, every
    /// probe allowed, so the refusal list refuses).
    pub(crate) deny_dryrun: bool,
    /// The first request word (upper case) never answered: the connection
    /// stays open and silent from then on.
    pub(crate) hang_on: Option<&'static str>,
    /// Pause before each answer.
    pub(crate) delay: Duration,
}

impl Fake {
    pub(crate) fn new(id: i64) -> Self {
        Self {
            id,
            run: "run-a",
            replica: false,
            deny_dryrun: false,
            hang_on: None,
            delay: Duration::ZERO,
        }
    }
}

/// Hands one stand-in connection per `conns` entry, in order, to the next
/// sessions of `target_id`.
pub(crate) fn serve(target_id: &str, conns: &[Fake]) {
    for fake in conns.iter().copied() {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        crate::node::push_test_transport(target_id, crate::net::Transport::Unix(client));
        tokio::spawn(answer(server, fake));
    }
}

async fn answer(server: tokio::net::UnixStream, fake: Fake) {
    let (r, mut w) = server.into_split();
    let mut r = BufReader::new(r);
    loop {
        // One request: an array of bulk strings.
        let mut line = String::new();
        if r.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let Ok(count) = line.trim_start_matches('*').trim().parse::<usize>() else {
            return;
        };
        let mut args = Vec::new();
        for _ in 0..count {
            let mut len = String::new();
            if r.read_line(&mut len).await.unwrap_or(0) == 0 {
                return;
            }
            let Ok(len) = len.trim_start_matches('$').trim().parse::<usize>() else {
                return;
            };
            let mut buf = vec![0u8; len + 2];
            if r.read_exact(&mut buf).await.is_err() {
                return;
            }
            buf.truncate(len);
            args.push(String::from_utf8_lossy(&buf).to_ascii_uppercase());
        }
        let word = args.first().map_or("", String::as_str);
        if fake.hang_on == Some(word) {
            std::future::pending::<()>().await;
        }
        let id = fake.id;
        let reply = match word {
            "HELLO" => format!(
                "%3\r\n$5\r\nproto\r\n:3\r\n$2\r\nid\r\n:{id}\r\n\
                 $4\r\nmode\r\n$10\r\nstandalone\r\n"
            ),
            "INFO" => {
                let text = match args.get(1).map(String::as_str) {
                    Some("SERVER") => format!(
                        "server_name:valkey\r\nvalkey_version:9.0.6\r\n\
                         redis_version:7.2.4\r\nrun_id:{}\r\n",
                        fake.run
                    ),
                    Some("REPLICATION") if fake.replica => "role:slave\r\n".to_owned(),
                    Some("REPLICATION") => "role:master\r\n".to_owned(),
                    Some("KEYSPACE") => String::new(),
                    _ => "cluster_enabled:0\r\n".to_owned(),
                };
                format!("${}\r\n{text}\r\n", text.len())
            }
            "ACL" if fake.deny_dryrun => {
                "+User databastion has no permissions to run the 'x' command\r\n".to_owned()
            }
            _ => "+OK\r\n".to_owned(),
        };
        if !fake.delay.is_zero() {
            tokio::time::sleep(fake.delay).await;
        }
        if w.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}
