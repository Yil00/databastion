# ADR-0006: Declared targets + local detection, no network scanning

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
The initial scope mentioned "automatic database discovery" without specifying the mechanism. An agent that scans the network would be noisy, would trigger IDSs, and would go against least privilege.

## Decision
- **Source of truth**: the targets declared in `agent.yaml` (engine, host/socket, account, secret reference).
- **Local detection** (suggestion only): the agent spots engines present **on its host** (Unix sockets `/var/run/postgresql`, `/run/mysqld`, local listening ports 5432/3306/27017/389, `postgres`, `mariadbd`, `mongod`, `slapd` processes). It reports them in the heartbeat as "detected, unconfigured targets". The console displays them with a configuration wizard.
- The agent **never** attempts to connect to a target without configured credentials, and scans no remote address.
- No access to the Docker socket.

## Consequences
- No surprises for the network team.
- The "automatic database discovery" success criterion becomes: "the agent reports the engines present on its host".
