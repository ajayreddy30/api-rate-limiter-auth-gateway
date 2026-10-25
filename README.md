# API Rate Limiter & Authentication Gateway

Spring Cloud Gateway (reactive) in front of two Spring Boot services, with JWT authentication, role-based
authorization and Redis token-bucket rate limiting.

```
 Client ──HTTPS──> [Caddy TLS]* ──> api-gateway :8080 ──┬──> auth-service    :8081 ── auth-db (PostgreSQL)
                                     │ 1 security headers │
                                     │ 2 HTTPS check      └──> product-service :8082 ── product-db (PostgreSQL)
                                     │ 3 strip spoofable headers
                                     │ 4 route allow-list + JWT + role check          * production only
                                     │ 5 rate limit  <──> Redis (atomic Lua token bucket)
                                     │ 6 add internal key + verified identity headers
```

Only the gateway is reachable. Backends sit on a private Docker network and additionally refuse any request that
does not carry the gateway's secret `X-Internal-Key`.

## Run it locally (Windows PowerShell; Linux/macOS use the `.sh` scripts)

Prerequisite: Docker Desktop.

```powershell
.\scripts\generate-env.ps1          # creates .env with random secrets, prints the first admin password
docker compose -f docker-compose.yml -f docker-compose.local.yml up --build
```

First build takes a few minutes. When all containers are up, in a **second** PowerShell window:

```powershell
.\scripts\load-env.ps1              # loads .env into this window (secrets are not printed)
.\scripts\smoke-test.ps1            # ~25 checks: auth, roles, validation, headers, rate limit
```

Every line should print `[PASS]`. Prefer Postman? Import `postman/secure-gateway.postman_collection.json`,
set the collection variables `adminUsername` / `adminPassword` (from your `.env`), and run it with the Collection Runner.

Stop with `docker compose -f docker-compose.yml -f docker-compose.local.yml down` (add `-v` to also delete the databases).

## Run the unit tests

```powershell
cd auth-service;    mvn test; cd ..
cd product-service; mvn test; cd ..
cd api-gateway;     mvn test; cd ..
```

The gateway's token-bucket integration test needs a real Redis and skips itself without one. To include it:

```powershell
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d redis
.\scripts\load-env.ps1
cd api-gateway; mvn test
```

## Run the services from your IDE instead of Docker

```powershell
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d redis auth-db product-db
# one PowerShell window per service:
.\scripts\load-env.ps1; cd auth-service;    mvn spring-boot:run
.\scripts\load-env.ps1; cd product-service; mvn spring-boot:run
.\scripts\load-env.ps1; cd api-gateway;     mvn spring-boot:run
```

## API

| Method & path | Who | Rate tier |
|---|---|---|
| `POST /auth/register` `{username, password}` | public (always creates a CUSTOMER) | register: 10 / 10 min / IP |
| `POST /auth/login` `{username, password}` | public | login: 10 / min / IP, plus account lock after 5 failures |
| `GET /products`, `GET /products/{id}` | any logged-in role | read: 60 / min / user |
| `POST /products` `{name, price}` | ADMIN, SELLER | write: 20 / min / user |
| `DELETE /products/{id}` | ADMIN (any), SELLER (own products only) | write |
| `GET /auth/admin/users` | ADMIN | read |
| `PUT /auth/admin/users/{username}/role` `{role}` | ADMIN | write |

Anything else returns 404 (unknown path), 405 (wrong method) or 400 (unsafe path). Send the token as
`Authorization: Bearer <accessToken>`. Tokens last 15 minutes. Password rules: 10-72 characters, at least one letter
and one digit, must not contain the username.

Rate-limit responses: `429` with `Retry-After`; every limited response also carries `X-RateLimit-Limit` and
`X-RateLimit-Remaining`. If Redis is down: login/register return `503` (fail closed), other routes continue (fail open).

## Deploy (single VPS)

1. Point a DNS name at the server; install Docker.
2. `scripts/generate-env.sh`, then edit `.env`: `DOMAIN=api.example.com`, `CORS_ALLOWED_ORIGINS=` (your front-end origin, if any).
   Remove the two `BOOTSTRAP_ADMIN_*` lines after the first start.
3. `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build`
4. Only ports 80/443 (Caddy) are public. Caddy gets the certificate automatically; the gateway then enforces HTTPS and trusts exactly one proxy hop.

Read `SECURITY.md` before going live.

## Project layout

```
auth-service/      users, BCrypt, lockout, JWT issuing, admin user routes   (Spring MVC + JPA + PostgreSQL)
product-service/   product CRUD with ownership checks                        (Spring MVC + JPA + PostgreSQL)
api-gateway/       filters, route policy, JWT validation, rate limiter       (Spring Cloud Gateway, reactive)
scripts/           generate-env, load-env, smoke-test, audit, backup
postman/           importable collection
```
