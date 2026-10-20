# Loads .env into the CURRENT PowerShell window and adds local (non-Docker) defaults, so that
# `mvn spring-boot:run` can start each service on your machine. Run it in every terminal you open:
#   .\scripts\load-env.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $root '.env'

if (-not (Test-Path $envFile)) {
    Write-Host "No .env found. Run .\scripts\generate-env.ps1 first." -ForegroundColor Red
    exit 1
}

Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -eq '' -or $line.StartsWith('#')) { return }
    $idx = $line.IndexOf('=')
    if ($idx -lt 1) { return }
    $name = $line.Substring(0, $idx).Trim()
    $value = $line.Substring($idx + 1).Trim()
    Set-Item -Path "Env:$name" -Value $value
}

# Local defaults: services run on the host, databases/Redis run from docker-compose.local.yml (loopback ports).
$env:AUTH_DB_URL         = "jdbc:postgresql://localhost:5432/$($env:AUTH_DB_NAME)"
$env:PRODUCT_DB_URL      = "jdbc:postgresql://localhost:5433/$($env:PRODUCT_DB_NAME)"
$env:REDIS_HOST          = 'localhost'
$env:AUTH_SERVICE_URL    = 'http://localhost:8081'
$env:PRODUCT_SERVICE_URL = 'http://localhost:8082'
$env:REQUIRE_HTTPS       = 'false'
$env:TRUSTED_PROXY_HOPS  = '0'
$env:TEST_REDIS_PASSWORD = $env:REDIS_PASSWORD

Write-Host "Environment loaded for this window (secrets are NOT printed)." -ForegroundColor Green
