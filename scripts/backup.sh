#!/usr/bin/env bash
# Dumps both databases from the running compose stack into ./backups (git-ignored).
# Restore example:
#   docker compose cp backups/auth-<stamp>.dump auth-db:/tmp/restore.dump
#   docker compose exec auth-db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists /tmp/restore.dump'
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p backups
stamp="$(date +%Y%m%d-%H%M%S)"
for svc in auth product; do
  docker compose exec -T "${svc}-db" sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f /tmp/backup.dump'
  docker compose cp "${svc}-db:/tmp/backup.dump" "backups/${svc}-${stamp}.dump"
  docker compose exec -T "${svc}-db" rm -f /tmp/backup.dump
  echo "backups/${svc}-${stamp}.dump written"
done
echo "Copy ./backups to encrypted off-host storage and test a restore regularly."
