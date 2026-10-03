# DataBastion developer entry points: `make help` lists them by section. They wrap the commands that
# contributors and CI (.github/workflows/) already run, with the same flags. Dev environment
# details: dev/README.md; console: console/README.md; agent: agent/README.md; e2e: e2e/README.md.
# Every target that waits is bounded by `timeout` (except the interactive console-dev,
# console-worker and agent-run, which run until Ctrl-C).

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
COMPOSE := docker compose -f dev/docker-compose.yml
UP_TIMEOUT ?= 900
WAIT_TIMEOUT ?= 600
TAIL ?= 200
LOG_DIRS := postgres mariadb mongodb percona psmdb
# pnpm at the version pinned by console/package.json (`packageManager`), through corepack.
PNPM ?= corepack pnpm
export COREPACK_ENABLE_DOWNLOAD_PROMPT ?= 0
# Same @redocly/cli version as the CI Protocol job.
REDOCLY := npx --yes @redocly/cli@2.54.3
CARGO_TIMEOUT ?= 1800
NODE_TIMEOUT ?= 900
# Connector integration tests: postgres, mysql, mongodb, openldap or all.
ENGINE ?= all
# Seconds: the CI e2e job has a 45 min budget, the load job 60 min.
E2E_TIMEOUT ?= 2700
LOAD_TIMEOUT ?= 3600
FUZZ_SECONDS ?= 10
# Agent configuration for `make agent-run`: no default (agent/README.md, "Commands").
AGENT_CONFIG ?=

.PHONY: help \
	install doctor \
	dev-dirs dev-metrics-token dev dev-smoke dev-down dev-reset dev-logs dev-ps seed seed-check test-dev \
	console-dev console-worker console-migrate console-lint console-typecheck console-test console-build \
	console-licenses \
	agent-build agent-build-minimal agent-fmt agent-lint agent-test agent-holdout agent-deny agent-it \
	agent-fuzz agent-run \
	protocol-lint protocol-append-only protocol-test protocol-drift protocol-check \
	docs-check shell-lint test-scripts test-e2e test-load fmt lint test check ci \
	e2e load-test \
	release-dry bump

##@ Help

help: ## List the targets (this list)
	@awk 'BEGIN { FS = ":.*## " } \
	  /^##@ / { printf "%s%s\n", (n++ ? "\n" : ""), substr($$0, 5); next } \
	  /^[a-z][a-z0-9-]*:.*## / { printf "  %-22s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo
	@echo "Variables: ENGINE, AGENT_CONFIG, VERSION, UP_TIMEOUT, WAIT_TIMEOUT, TAIL, E2E_TIMEOUT,"
	@echo "LOAD_TIMEOUT, FUZZ_SECONDS, CARGO_TIMEOUT, NODE_TIMEOUT, PNPM (e.g. make agent-it ENGINE=postgres)."

##@ Setup

install: ## Install dependencies as CI does: console (pnpm, frozen lockfile), root and protocol (npm ci), cargo fetch
	cd console && timeout $(NODE_TIMEOUT) $(PNPM) install --frozen-lockfile
	timeout $(NODE_TIMEOUT) npm ci --ignore-scripts
	cd shared/protocol && timeout $(NODE_TIMEOUT) npm ci --ignore-scripts
	cd agent && timeout $(CARGO_TIMEOUT) cargo fetch --locked
	cd agent/fuzz && timeout $(CARGO_TIMEOUT) cargo fetch --locked

doctor: ## Print tool versions; fail with the list of missing tools
	@missing=""; \
	check() { local name="$$1" out; shift; \
	  out="$$({ timeout 120 "$$@" 2>/dev/null || true; } | head -n 1)"; if [ -n "$$out" ]; then printf '  %-15s %s\n' "$$name" "$$out"; \
	  else printf '  %-15s MISSING\n' "$$name"; missing="$$missing, $$name"; fi; }; \
	echo "Required:"; \
	check git git --version; \
	check make make --version; \
	check timeout timeout --version; \
	check node node --version; \
	check npm npm --version; \
	check corepack corepack --version; \
	check pnpm bash -c 'cd console && $(PNPM) --version'; \
	check cargo cargo --version; \
	check rustc rustc --version; \
	check rustfmt rustfmt --version; \
	check clippy cargo clippy --version; \
	check python3 python3 --version; \
	check docker docker --version; \
	check "docker compose" docker compose version; \
	echo "Optional (CI gates: agent-deny, shell-lint; e2e, load-test):"; \
	opt() { local name="$$1" out; shift; \
	  out="$$({ timeout 60 "$$@" 2>/dev/null || true; } | grep -E '[0-9]+\.[0-9]+' | head -n 1 | cut -c 1-60 || true)"; if [ -n "$$out" ]; then printf '  %-15s %s\n' "$$name" "$$out"; \
	  else printf '  %-15s not found\n' "$$name"; fi; }; \
	opt cargo-deny cargo deny --version; \
	opt shellcheck shellcheck --version; \
	opt jq jq --version; \
	opt openssl openssl version; \
	opt curl curl --version; \
	if command -v docker >/dev/null && ! timeout 30 docker info >/dev/null 2>&1; then \
	  echo "warning: the Docker daemon is not reachable: dev, agent-it, e2e and load-test need it"; fi; \
	if [ -n "$$missing" ]; then echo "doctor: missing: $${missing#, }" >&2; exit 1; fi; \
	echo "All required tools found."

##@ Dev environment (Docker; dev/README.md)

dev/.env:
	cp dev/.env.example dev/.env

dev-dirs: ## Create the engine log directories (world-writable: engines run as non-root users)
	mkdir -p $(addprefix dev/.state/logs/,$(LOG_DIRS))
	chmod 0777 $(addprefix dev/.state/logs/,$(LOG_DIRS))

dev-metrics-token: ## Create dev/.state/metrics_token (48 random chars, 0600) if missing; never committed
	@mkdir -p dev/.state
	@if [ -d dev/.state/metrics_token ]; then rmdir dev/.state/metrics_token; fi
	@if [ ! -f dev/.state/metrics_token ] || [ ! -s dev/.state/metrics_token ]; then \
	  (umask 077; head -c 36 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n' > dev/.state/metrics_token); \
	  echo "Generated dev/.state/metrics_token"; \
	fi
	@chmod 0600 dev/.state/metrics_token

dev: dev/.env dev-dirs dev-metrics-token ## Start the dev environment (databases, Mailpit, Prometheus, Grafana) and wait until healthy
	timeout $(UP_TIMEOUT) $(COMPOSE) up -d --build --wait --wait-timeout $(WAIT_TIMEOUT)
	@echo "Dev environment ready. Console and agent are not containerized yet: see dev/README.md."

dev-smoke: dev/.env ## Smoke-test a running dev environment (accounts, audit logs, UIs)
	timeout 300 dev/smoke-test.sh

dev-down: ## Stop the dev environment (keeps data volumes)
	timeout 180 $(COMPOSE) down --remove-orphans

dev-reset: ## Stop and delete volumes and dev/.state (reloads the seed on next `make dev`)
	timeout 180 $(COMPOSE) down -v --remove-orphans
	rm -rf dev/.state

dev-logs: ## Show the last TAIL (200) log lines of every service (not followed)
	timeout 60 $(COMPOSE) logs --no-color --tail=$(TAIL)

dev-ps: ## Show service status and health
	timeout 60 $(COMPOSE) ps

seed: ## Regenerate dev/seed/out/* and dev/ground-truth.json (then `make dev-reset dev` to reload)
	timeout 120 python3 dev/seed/generate.py

seed-check: ## Fail if the committed seed files are out of date
	timeout 120 python3 dev/seed/generate.py --check

test-dev: ## Unit tests of the seed generator
	timeout 300 python3 -m unittest discover -s dev/seed -v

##@ Console (console/; environment variables: console/README.md)

console-dev: ## INTERACTIVE (until Ctrl-C): next dev; needs DATABASE_URL and a migrated database
	cd console && $(PNPM) dev

console-worker: ## INTERACTIVE (until Ctrl-C): the pg-boss worker; needs DATABASE_URL
	cd console && $(PNPM) worker

console-migrate: ## Apply migrations: DATABASE_URL(_FILE); owner role: DATABASE_MIGRATION_URL(_FILE)
	@if [ -z "$${DATABASE_URL:-}$${DATABASE_URL_FILE:-}" ]; then \
	  echo "console-migrate: set DATABASE_URL or DATABASE_URL_FILE, plus DATABASE_MIGRATION_URL(_FILE) for a separate owner role (console/README.md)" >&2; \
	  exit 2; fi
	cd console && timeout 600 $(PNPM) db:migrate

console-lint: ## ESLint, no warning allowed (CI)
	cd console && timeout $(NODE_TIMEOUT) $(PNPM) lint

console-typecheck: ## next typegen + tsc --noEmit (CI)
	cd console && timeout $(NODE_TIMEOUT) $(PNPM) typecheck

console-test: ## vitest run; DB / Mailpit suites skip without TEST_DATABASE_URL (or PG_BIN) / DATABASTION_TEST_SMTP
	cd console && timeout $(NODE_TIMEOUT) $(PNPM) test

console-build: ## Production build + wake-up check (CI)
	cd console && timeout $(NODE_TIMEOUT) $(PNPM) build

console-licenses: ## License gate on the production dependencies (invariant I7, CI)
	timeout 60 python3 -m unittest discover -s scripts -p 'test_check_console_licenses.py'
	tmp="$$(mktemp)"; trap 'rm -f "$$tmp"' EXIT; \
	  (cd console && timeout 300 $(PNPM) licenses list --prod --json) > "$$tmp"; \
	  python3 scripts/check_console_licenses.py "$$tmp"

##@ Agent (agent/; commands: agent/README.md)

agent-build: ## Release build (agent/target/release/databastion-agent), as the agent Dockerfile
	cd agent && timeout $(CARGO_TIMEOUT) cargo build --release --locked -p databastion-agent

agent-build-minimal: ## Minimal build without connectors (CI)
	cd agent && timeout $(CARGO_TIMEOUT) cargo build --no-default-features --locked

agent-fmt: ## cargo fmt (rewrites files)
	cd agent && timeout 300 cargo fmt --all

agent-lint: ## cargo fmt --check + clippy -D warnings (CI)
	cd agent && timeout 300 cargo fmt --all --check
	cd agent && timeout $(CARGO_TIMEOUT) cargo clippy --all-targets --all-features --locked -- -D warnings

agent-test: ## Unit and contract tests (CI); connector integration tests skip without their env vars
	cd agent && timeout $(CARGO_TIMEOUT) cargo test --all-features --locked

agent-holdout: ## Held-out classifier gate (phase 2 exit criterion, CI)
	timeout 120 python3 dev/holdout/generate.py --check
	timeout 120 python3 dev/holdout/generate.py > /dev/null
	cd agent && timeout $(CARGO_TIMEOUT) cargo test -p databastion-classifiers --test holdout --all-features --locked -- --ignored --nocapture

agent-deny: ## cargo-deny bans / licenses / sources, dev-dependencies too (CI; needs cargo-deny)
	cd agent && timeout 600 cargo deny --locked check bans licenses sources
	cd agent && timeout 600 cargo deny --config deny-dev.toml --locked check licenses sources

agent-it: ## Connector integration tests on the running dev env (`make dev`); ENGINE=postgres|mysql|mongodb|openldap|all
	timeout $(CARGO_TIMEOUT) dev/agent-it.sh $(ENGINE)

agent-fuzz: ## Fuzz smoke run of the parser targets, FUZZ_SECONDS each (CI: 10)
	timeout $(CARGO_TIMEOUT) agent/fuzz/smoke.sh $(FUZZ_SECONDS)

agent-run: ## INTERACTIVE (until Ctrl-C): the agent with AGENT_CONFIG=<agent.yaml>, enrolled first
	@if [ -z "$(AGENT_CONFIG)" ]; then \
	  echo "agent-run: set AGENT_CONFIG=<path to agent.yaml>. There is no ready dev configuration: start" >&2; \
	  echo "from agent/agent.example.yaml and enroll first (agent/README.md, \"Commands\"):" >&2; \
	  echo "  cd agent && cargo run -p databastion-agent -- enroll --config <agent.yaml> --token-file <token file>" >&2; \
	  exit 2; fi
	cd agent && cargo run --locked -p databastion-agent -- run --config "$(abspath $(AGENT_CONFIG))"

##@ Protocol (shared/protocol/)

protocol-lint: ## Redocly lint of openapi.yaml (CI; npx downloads @redocly/cli)
	timeout 300 $(REDOCLY) lint shared/protocol/openapi.yaml

protocol-append-only: ## Registries are append-only against origin/dev and origin/main (git fetch first)
	timeout 120 python3 shared/protocol/scripts/append-only.py origin/dev origin/main

protocol-test: ## Contract tests: schemas, registries, fixtures (CI; needs `make install`)
	cd shared/protocol && timeout 300 npm test

protocol-drift: ## Generated agent and console types match openapi.yaml (codegen drift tests)
	cd agent && timeout $(CARGO_TIMEOUT) cargo test -p databastion-protocol --all-features --locked --test drift
	cd console && timeout $(NODE_TIMEOUT) $(PNPM) exec vitest run src/lib/protocol/generated.test.ts

protocol-check: protocol-lint protocol-append-only protocol-test protocol-drift ## All of the above

##@ Quality / CI

docs-check: ## Internal Markdown links (CI)
	timeout 120 python3 scripts/check-md-links.py

shell-lint: ## shellcheck of the load harness (CI) and dev/agent-it.sh
	timeout 120 shellcheck -x e2e/load/run.sh e2e/load/initdb/*.sh dev/agent-it.sh

test-scripts: ## Unit tests of scripts/ and the release settings check fixtures (CI)
	timeout 60 python3 -m unittest discover -s scripts -p 'test_*.py'
	timeout 60 .github/scripts/test_check_release_settings.sh

test-e2e: ## Unit tests of the e2e I2 leak scanner (CI)
	timeout 120 python3 -m unittest discover -s e2e -p 'test_*.py' -v

test-load: ## Unit tests of the load harness (CI)
	timeout 120 python3 -m unittest discover -s e2e/load -p 'test_*.py' -v

fmt: agent-fmt ## Format the code (agent; the console has no formatter: ESLint only)

lint: console-lint console-typecheck agent-lint protocol-lint shell-lint ## Every linter

test: console-test agent-test protocol-test test-dev test-e2e test-load test-scripts ## Every fast unit test (no container)

check: lint test docs-check seed-check protocol-append-only ## lint + test + docs-check: what CI runs, minus containers and `make ci`'s slow gates

ci: check console-licenses console-build agent-holdout agent-build-minimal agent-deny agent-fuzz ## check + the other non-container CI gates (slow)

##@ End-to-end (Docker)

e2e: test-e2e ## LONG: end-to-end harness in containers (e2e/run.sh, at most E2E_TIMEOUT s)
	timeout $(E2E_TIMEOUT) e2e/run.sh

load-test: test-load ## LONG (about 1 h): load / database impact test (e2e/load/run.sh, at most LOAD_TIMEOUT s)
	timeout $(LOAD_TIMEOUT) e2e/load/run.sh

##@ Release (maintainer)

release-dry: ## release-it dry run (on branch main only, .release-it.json; needs `make install`)
	timeout 300 npm run release:dry

bump: ## Align every component's version: VERSION=x.y.z (normally run by the release CI, not by hand)
	@if [ -z "$(VERSION)" ]; then echo "bump: set VERSION=x.y.z (normally the release CI runs it: RELEASE.md)" >&2; exit 2; fi
	timeout 300 node scripts/bump-version.mjs "$(VERSION)"
