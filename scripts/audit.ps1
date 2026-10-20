# Local security audit helper (Windows PowerShell). Read-only: prints findings, never changes files.
Set-Location (Split-Path -Parent $PSScriptRoot)
$script:findings = 0
function Warn($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow; $script:findings++ }
function Ok($m)   { Write-Host "[ OK ] $m" -ForegroundColor Green }

Write-Host "== 1. Secrets in the working tree =="
$patterns = @('BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY', 'AKIA[0-9A-Z]{16}', 'this-is-a-demo-secret')
$files = Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(\.git|target|node_modules)\\' -and $_.Name -notin @('.env', '.env.example', 'audit.ps1', 'audit.sh') }
$hits = $files | Select-String -Pattern $patterns
if ($hits) { $hits | ForEach-Object { Write-Host "$($_.Path):$($_.LineNumber)" }; Warn "Possible secret material found above." }
else { Ok "No private keys / AWS keys / old demo secret in sources." }

Write-Host "== 2. Is .env tracked by git? =="
$inRepo = (git rev-parse --is-inside-work-tree 2>$null)
if ($inRepo -eq 'true') {
    git ls-files --error-unmatch .env 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Warn ".env is TRACKED by git - run: git rm --cached .env" } else { Ok ".env is not tracked." }

    Write-Host "== 3. Secrets in git history =="
    $demo = git log --all --oneline -S'this-is-a-demo-secret' 2>$null
    if ($demo) { Warn "The old demo JWT secret exists in git history (public knowledge). The new JWT_SECRET must differ - it does if you used generate-env." }
    else { Ok "Old demo secret not found in history." }
    $added = git log --all --diff-filter=A --name-only --pretty=format: -- .env '*.pem' '*.key' '*.p12' 2>$null | Where-Object { $_ }
    if ($added) { Warn "A .env/.pem/.key file was committed at some point. Rotate every secret in it and purge history (git filter-repo)." }
    else { Ok "No .env/.pem/.key files ever added to history." }
    if (Get-Command gitleaks -ErrorAction SilentlyContinue) { gitleaks detect --source . --redact }
    else { Write-Host "[INFO] gitleaks not installed - install it and run: gitleaks detect --source . --redact" }
} else { Write-Host "[INFO] Not a git repository yet - run 'git init' first, then re-run this script." }

Write-Host "== 4. Dependencies =="
Write-Host "Run in each module (auth-service, product-service, api-gateway):"
Write-Host "  mvn -q versions:display-dependency-updates"
Write-Host "  mvn org.owasp:dependency-check-maven:check     # needs network"
if ($script:findings -gt 0) { exit 1 }
