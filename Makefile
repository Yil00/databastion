# DataBastion developer entry points. Dev environment details: dev/README.md.
# Every target that waits is bounded by `timeout`.

SHELL := /bin/bash
COMPOSE := docker compose -f dev/docker-compose.yml
UP_TIMEOUT ?= 900
WAIT_TIMEOUT ?= 600
TAIL ?= 200
LOG_DIRS := postgres mariadb mongodb

.PHONY: help dev-dirs dev-metrics-token dev dev-smoke dev-down dev-reset dev-logs dev-ps seed seed-check test-dev

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

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

dev-logs: ## Show the last $(TAIL) log lines of every service (not followed)
	timeout 60 $(COMPOSE) logs --no-color --tail=$(TAIL)

dev-ps: ## Show service status and health
	timeout 60 $(COMPOSE) ps

seed: ## Regenerate dev/seed/out/* and dev/ground-truth.json (then `make dev-reset dev` to reload)
	timeout 120 python3 dev/seed/generate.py

seed-check: ## Fail if the committed seed files are out of date
	timeout 120 python3 dev/seed/generate.py --check

test-dev: ## Unit tests of the seed generator
	timeout 300 python3 -m unittest discover -s dev/seed -v
