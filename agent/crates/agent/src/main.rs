//! `databastion-agent`: the DataBastion agent binary (ADR-0002).
//!
//! The agent is an HTTPS client only: this binary opens no listening socket
//! (invariant I1). Logs are structured JSON on stdout and never contain a
//! sampled value (I2).
//!
//! Skeleton status (P0-D): parses the command line, logs startup and the
//! compiled-in connectors, then exits.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use databastion_core::{Connector, Engine};
use tracing_subscriber::EnvFilter;

/// Environment variable holding the log filter (`tracing` directives).
const LOG_ENV: &str = "DATABASTION_LOG";

/// DataBastion agent.
#[derive(Debug, Parser)]
#[command(name = "databastion-agent", version, about)]
struct Cli {
    /// Path to the agent configuration file (`agent.yaml`).
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
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

fn init_logging() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .with_current_span(false)
        .with_span_list(false)
        .try_init()
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if init_logging().is_err() {
        return ExitCode::FAILURE;
    }

    let engines: Vec<&str> = compiled_engines().into_iter().map(Engine::as_str).collect();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        connectors = ?engines,
        "databastion-agent starting"
    );
    tracing::warn!(
        "skeleton build: configuration loading, enrollment and uplink are not implemented yet"
    );
    tracing::info!("databastion-agent stopped");
    ExitCode::SUCCESS
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
    fn cli_parses_config_path() {
        let cli = Cli::try_parse_from([
            "databastion-agent",
            "--config",
            "/etc/databastion/agent.yaml",
        ])
        .unwrap();
        assert_eq!(cli.config, PathBuf::from("/etc/databastion/agent.yaml"));
    }

    #[test]
    fn cli_requires_config() {
        assert!(Cli::try_parse_from(["databastion-agent"]).is_err());
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
