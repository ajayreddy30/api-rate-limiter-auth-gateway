#!/usr/bin/env bash
# Local security audit helper. Read-only: it prints findings and never changes files.
cd "$(dirname "$0")/.."
status=0
warn() { echo "[WARN] $*"; status=1; }
ok()   { echo "[ OK ] $*"; }

echo "== 1. Secrets in the working tree =="
if grep -RInE --exclude-dir={.git,target,node_modules} --exclude=.env --exclude=.env.example --exclude=audit.sh --exclude=audit.ps1 \
     -e 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' -e 'AKIA[0-9A-Z]{16}' -e 'this-is-a-demo-secret' . ; then
  warn "Possible secret material found above."
else ok "No private keys / AWS keys / old demo secret in tracked sources."; fi

echo "== 2. Is .env tracked by git? =="
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git ls-files --error-unmatch .env >/dev/null 2>&1; then warn ".env is TRACKED by git - run: git rm --cached .env"; else ok ".env is not tracked."; fi

  echo "== 3. Secrets in git history =="
  if [ -n "$(git log --all --oneline -S'this-is-a-demo-secret' 2>/dev/null)" ]; then
    warn "The old demo JWT secret exists in git history. It is public knowledge - the new JWT_SECRET must differ (it does if you used generate-env)."
  else ok "Old demo secret not found in history."; fi
  if [ -n "$(git log --all --diff-filter=A --name-only --pretty=format: -- .env '*.pem' '*.key' '*.p12' 2>/dev/null | sort -u | grep -v '^$')" ]; then
    warn "A .env/.pem/.key file was committed at some point. Rotate every secret in it and purge history (git filter-repo)."
  else ok "No .env/.pem/.key files ever added to history."; fi
  if command -v gitleaks >/dev/null 2>&1; then gitleaks detect --source . --redact || status=1
  else echo "[INFO] gitleaks not installed - install it and run: gitleaks detect --source . --redact"; fi
else echo "[INFO] Not a git repository yet - run 'git init' first, then re-run this script."; fi

echo "== 4. Dependencies =="
echo "Run in each module (auth-service, product-service, api-gateway):"
echo "  mvn -q versions:display-dependency-updates"
echo "  mvn org.owasp:dependency-check-maven:check     # needs network; add -DnvdApiKey=<key> for speed"
exit $status
