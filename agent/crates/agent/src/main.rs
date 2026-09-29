//! `databastion-agent`: the DataBastion agent binary (ADR-0002).
//!
//! The agent is an HTTPS client only: this binary opens no listening socket
//! (invariant I1). Logs are structured JSON on stdout and never contain a
//! sampled value (I2) nor a secret.
//!
//! Subcommands:
//! - `enroll --config <agent.yaml> --token-file <path>`: exchanges a
//!   single-use enrollment token for an identity (`0600`) and generates the
//!   local HMAC key;
//! - `run --config <agent.yaml>`: heartbeat and jobs loops until SIGTERM /
//!   SIGINT.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use databastion_core::{AgentConfig, Connector, Engine, EnrollOptions};
use tokio::sync::watch;
use tracing::Level;
use tracing_subscriber::filter::{EnvFilter, filter_fn};
use tracing_subscriber::prelude::*;

/// Environment variable holding the log filter (`tracing` directives).
const LOG_ENV: &str = "DATABASTION_LOG";

/// DataBastion agent.
#[derive(Debug, Parser)]
#[command(name = "databastion-agent", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enroll this agent with a single-use token from the console.
    Enroll {
        /// Path to the agent configuration file (`agent.yaml`).
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        /// File holding the enrollment token (never pass it on the command
        /// line: it would be visible in the process list).
        #[arg(long, value_name = "PATH", env = "DATABASTION_ENROLLMENT_TOKEN_FILE")]
        token_file: PathBuf,
        /// Replace an existing identity. Revoke the old agent in the console
        /// first: its secret stays valid until revoked.
        #[arg(long)]
        force: bool,
        /// With --force, also replace the local HMAC key (fingerprints will
        /// no longer correlate with earlier ones). Kept by default.
        #[arg(long, requires = "force")]
        new_hmac_key: bool,
    },
    /// Run the agent.
    Run {
        /// Path to the agent configuration file (`agent.yaml`).
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
}

/// Connectors compiled into this binary (Cargo features).
fn compiled_connectors() -> Vec<Box<dyn Connector>> {
    vec![
        #[cfg(feature = "postgres")]
        Box::new(databastion_connector_postgres::PostgresConnector::new()),
        #[cfg(feature = "mysql")]
        Box::new(databastion_connector_mysql::MysqlConnector::new()),
        #[cfg(feature = "mongodb")]
        Box::new(databastion_connector_mongodb::MongodbConnector::new()),
        #[cfg(feature = "openldap")]
        Box::new(databastion_connector_openldap::OpenldapConnector::new()),
    ]
}

fn compiled_engines() -> Vec<Engine> {
    compiled_connectors().iter().map(|c| c.engine()).collect()
}

/// Hard cap applied after `DATABASTION_LOG`: only DataBastion's own targets
/// may log below `warn`. Third-party crates (database drivers, HTTP client…)
/// can log query parameters or payloads at debug/trace level, which could
/// contain sampled values (I2).
fn third_party_capped(target: &str, level: Level) -> bool {
    target.starts_with("databastion_") || level <= Level::WARN
}

fn init_logging() -> Result<(), tracing_subscriber::util::TryInitError> {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new("info"));
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(std::io::stdout)
        .with_current_span(false)
        .with_span_list(false)
        .with_filter(filter)
        .with_filter(filter_fn(|meta| {
            third_party_capped(meta.target(), *meta.level())
        }));
    tracing_subscriber::registry().with(layer).try_init()
}

/// Resolves on SIGTERM or SIGINT.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = ctrl_c => {}
                _ = term.recv() => {}
            }
        }
        Err(_) => {
            let _ = ctrl_c.await;
        }
    }
}

async fn run(config: PathBuf) -> ExitCode {
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown requested");
        let _ = tx.send(true);
    });
    match databastion_core::run(&config, compiled_connectors(), rx).await {
        Ok(()) => {
            tracing::info!("databastion-agent stopped");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "databastion-agent stopped on error");
            ExitCode::FAILURE
        }
    }
}

async fn enroll(config: PathBuf, token_file: PathBuf, options: EnrollOptions) -> ExitCode {
    let config = match AgentConfig::load(&config) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(error = %e, "invalid configuration");
            return ExitCode::FAILURE;
        }
    };
    match databastion_core::enroll(&config, &token_file, options, &compiled_engines()).await {
        Ok(agent_id) => {
            tracing::info!(agent_id, "enrollment complete");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "enrollment failed");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if init_logging().is_err() {
        return ExitCode::FAILURE;
    }
    // Panics are logged by location only (their message can quote data),
    // from here on, enrollment included.
    databastion_core::install_panic_hook();

    let engines: Vec<&str> = compiled_engines().into_iter().map(Engine::as_str).collect();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        connectors = ?engines,
        "databastion-agent starting"
    );
    match cli.command {
        Command::Enroll {
            config,
            token_file,
            force,
            new_hmac_key,
        } => {
            let options = EnrollOptions {
                force,
                new_hmac_key,
            };
            enroll(config, token_file, options).await
        }
        Command::Run { config } => run(config).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_parses_run() {
        let cli = Cli::try_parse_from([
            "databastion-agent",
            "run",
            "--config",
            "/etc/databastion/agent.yaml",
        ])
        .unwrap();
        match cli.command {
            Command::Run { config } => {
                assert_eq!(config, PathBuf::from("/etc/databastion/agent.yaml"));
            }
            Command::Enroll { .. } => panic!("expected run"),
        }
    }

    #[test]
    fn cli_parses_enroll() {
        let cli = Cli::try_parse_from([
            "databastion-agent",
            "enroll",
            "--config",
            "/etc/databastion/agent.yaml",
            "--token-file",
            "/run/token",
            "--force",
        ])
        .unwrap();
        match cli.command {
            Command::Enroll {
                token_file, force, ..
            } => {
                assert_eq!(token_file, PathBuf::from("/run/token"));
                assert!(force);
            }
            Command::Run { .. } => panic!("expected enroll"),
        }
    }

    #[test]
    fn cli_requires_a_subcommand_and_config() {
        assert!(Cli::try_parse_from(["databastion-agent"]).is_err());
        assert!(Cli::try_parse_from(["databastion-agent", "run"]).is_err());
    }

    #[test]
    fn third_party_logs_are_capped_at_warn() {
        assert!(third_party_capped("sqlx::query", Level::WARN));
        assert!(third_party_capped("sqlx::query", Level::ERROR));
        assert!(!third_party_capped("sqlx::query", Level::INFO));
        assert!(!third_party_capped("hyper_util::client", Level::DEBUG));
        assert!(!third_party_capped("databastion", Level::TRACE));
    }

    #[test]
    fn own_targets_may_be_verbose() {
        assert!(third_party_capped("databastion_agent", Level::TRACE));
        assert!(third_party_capped("databastion_core::sink", Level::DEBUG));
    }

    #[test]
    fn compiled_connectors_follow_cargo_features() {
        let engines = compiled_engines();
        assert_eq!(
            engines.contains(&Engine::Postgres),
            cfg!(feature = "postgres")
        );
        assert_eq!(engines.contains(&Engine::Mysql), cfg!(feature = "mysql"));
        assert_eq!(
            engines.contains(&Engine::Mongodb),
            cfg!(feature = "mongodb")
        );
        assert_eq!(
            engines.contains(&Engine::Openldap),
            cfg!(feature = "openldap")
        );
    }
}
