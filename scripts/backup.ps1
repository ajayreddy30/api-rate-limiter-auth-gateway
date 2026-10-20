# Dumps both databases from the running compose stack into .\backups (git-ignored).
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
New-Item -ItemType Directory -Force -Path backups | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
foreach ($svc in @('auth', 'product')) {
    docker compose exec -T "$svc-db" sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f /tmp/backup.dump'
    docker compose cp "$svc-db:/tmp/backup.dump" "backups/$svc-$stamp.dump"
    docker compose exec -T "$svc-db" rm -f /tmp/backup.dump
    Write-Host "backups/$svc-$stamp.dump written"
}
Write-Host "Copy .\backups to encrypted off-host storage and test a restore regularly."
