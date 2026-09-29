# shellcheck shell=bash
# Sourced (not executed: no exec bit) by the MySQL / MariaDB entrypoint of the e2e targets, after
# 10-seed.sql and before dev's 20-databastion.sh, which creates the agent account from
# $DATABASTION_DB_PASSWORD. The dev compose file passes it in the environment; here it comes from
# the Docker secret, into a shell variable of the entrypoint only (not exported: mysqld and its
# children never see it, and it is never on a command line).
# shellcheck disable=SC2034 # read by 20-databastion.sh, sourced by the same shell
DATABASTION_DB_PASSWORD="$(cat /run/secrets/agent_password)"
