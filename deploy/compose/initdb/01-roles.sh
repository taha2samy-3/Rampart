#!/bin/sh
# Provisions the login roles with credentials from the environment (D4).
# The schema migration only guarantees the roles exist; it never sets passwords.
set -eu
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v app_pw="$RAMPART_APP_PASSWORD" -v sys_pw="$RAMPART_SYSTEM_PASSWORD" <<'SQL'
CREATE ROLE rampart_app    LOGIN PASSWORD :'app_pw';
CREATE ROLE rampart_system LOGIN BYPASSRLS PASSWORD :'sys_pw';
SQL
