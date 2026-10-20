# Security notes

## 1. What was and was not verified (read this first)

Verified in the build sandbox:
- All Java sources parse with the real `javac` (21). That check found one real compile error (a record accessor clashing with a
  static method), which is fixed.
- `pom.xml`, YAML, compose and JSON files are well-formed; no private keys, AWS keys or default secrets are present in the sources.

**NOT verified** (the sandbox has no Maven, no network and no Docker): the Maven build, the unit tests running and passing,
the Docker images building, the Lua script executing, Hibernate validating `schema.sql` against the entities, Spring
binding the Gateway properties, and any dependency vulnerability scan. Treat the first `mvn test` / `docker compose up` on your
machine as the real verification, and fix whatever it reports. CI (`.github/workflows/ci.yml`) repeats the build on every push.

## 2. Checklist status

| Area | Control | Where |
|---|---|---|
| **A. Auth/JWT** | Passwords hashed: BCrypt cost 12, per-hash salt, 10-72 chars, never logged | `AuthService`, `AppConfig` |
| | Signature verified; **HS256 pinned** (other algorithms, `alg:none`, encrypted tokens rejected) | `JwtValidator` |
| | Claims validated: issuer, audience, exp, iat, subject format, role whitelist, 30 s skew, 2 KB size cap | `JwtValidator` |
| | Secret only from env, >= 32 bytes, placeholder values refused, app will not start otherwise | `JwtService`, `JwtValidator` |
| | Expired / malformed / tampered tokens give an identical generic 401 (reason only in server log) | `AuthenticationFilter` |
| | Login abuse: 10 attempts/min/IP at the gateway **and** account lock (5 failures, 15 min), equal-time responses for unknown user / bad password / locked account | `RateLimitFilter`, `AuthService` |
| | Roles enforced twice: gateway route policy, then again in each service. Self-registration cannot choose a role; unknown JSON fields are rejected | `RoutePolicy`, controllers |
| **B. Rate limiter** | Enforced at the gateway, state in Redis, never in the client | `RateLimitFilter` |
| | Identity = verified JWT subject, or client IP (forwarded headers honoured only for configured trusted hops) | `ClientIpResolver` |
| | Check-and-take is one atomic Lua script; time comes from Redis `TIME` (no clock skew between gateways) | `token_bucket.lua` |
| | Algorithm: token bucket, continuous refill, capacity = burst; parameters per tier in `application.yml` | `RateLimitProperties` |
| | 429 + `Retry-After`; 503 when the limiter is down and the tier is fail-closed | `RateLimitFilter` |
| **C. API** | Bean Validation on every body, allow-listed characters for names (no markup stored), strict JSON, 16 KB body cap | DTOs, `application.yml` |
| | No tokens/passwords/secrets logged; attacker-supplied usernames not logged; request-detail logging off | all services |
| | CORS: no origin allowed unless listed in `CORS_ALLOWED_ORIGINS`; no wildcard; no credentials | `application.yml` |
| | Errors: fixed JSON messages, no stack traces, class names or SQL | `GlobalExceptionHandler`, `server.error.*` |
| | Method + path allow-list; percent-encoding, dot-segments and `//` refused | `RoutePolicy` |
| | Security headers on every response, `Server` removed | `SecurityHeadersFilter` |
| **D. Deployment** | Secrets only in `.env` (git-ignored); compose refuses to start with missing values | `.env.example`, compose |
| | One safe configuration, no debug mode, H2 console removed, schema never auto-modified | `application.properties` |
| | HTTPS enforced (plain HTTP refused; HSTS) + Caddy TLS for production | `HttpsEnforcementFilter`, `Caddyfile` |
| | Redis (password) and databases on an internal-only network, no published ports in the base stack | `docker-compose.yml` |
| | No Actuator dependency; nothing exposed even if added later | `application.yml` |
| | App containers: non-root user, read-only filesystem, all capabilities dropped, no-new-privileges | Dockerfiles, compose |
| | Backups: `scripts/backup.*` (pg_dump) + restore steps in that script | `scripts/` |
| **E. Evidence** | Auth, authz, validation, lockout, JWT attack cases, IP spoofing, headers, rate-limit boundary and concurrency tests | `src/test/**` |
| | Failure behaviour documented (section 4); CI + Dependabot + gitleaks configured | `.github/` |

## 3. Trust model

1. Clients can only reach the gateway. 2. The gateway deletes any incoming `X-User-*` / `X-Internal-Key` headers, verifies
the JWT, then adds `X-User-Name`, `X-User-Role` and the secret `X-Internal-Key`; it drops `Authorization` and `Cookie` before
proxying. 3. Backends reject any request without the exact internal key, which is why they can trust `X-User-*`.
If `INTERNAL_API_KEY` leaks, rotate it in `.env` and redeploy all three services.

## 4. Failure behaviour (documented decisions)

| Situation | Behaviour |
|---|---|
| Redis down / slow (> 300 ms) | login & register: **503** (fail closed, protects against brute force). read/write routes: **allowed** and logged at ERROR (fail open, keeps the API available). Change with `rate-limit.tiers.*.fail-open`. |
| Backend service down | Gateway returns 502/503/504 JSON without internals; connect timeout 2 s, response timeout 10 s. |
| Database down | The service returns 500 `{"error":"Internal server error","errorId":...}`; details only in its log. |
| Missing/short secret | The service refuses to start (message never contains the value). |

## 5. Known limitations (be honest about these in an interview)

- **Dependency posture.** Spring Boot **3.5.16** is the last 3.x release; open-source support for 3.x ended on 30 June 2026, so new
  CVEs will not be fixed on this line. Spring Boot 4.1.x is the current supported line, but it changes Gateway starters/properties,
  Jackson, Security and Hibernate, and cannot be verified blind. Plan: get this build green, then migrate to 4.1.x with Spring Cloud 2025.1.x
  in a separate commit. Run `mvn org.owasp:dependency-check-maven:check` and `mvn versions:display-dependency-updates` per module.
- No refresh tokens, logout or token revocation: a stolen token works until it expires (15 min). A role change applies at the user's next login.
- One shared HS256 secret between auth-service and gateway, with no key rotation. Next step: asymmetric keys (RS256/EdDSA) with a `kid` and JWKS.
- Account lockout can be used to lock someone else out for 15 minutes (the classic trade-off); the IP limit makes this expensive.
- Per-IP limits can affect many users behind one NAT.
- Redis is password protected but not TLS-encrypted (private network only); database/Redis containers keep their image defaults for capabilities.
- Input validation keeps markup out, but front-ends must still HTML-encode output.
- No circuit breakers, distributed tracing or metrics yet.

## 6. Before you deploy (checklist)

1. `.\scripts\audit.ps1` (checks sources, tracked `.env`, git history for the old demo secret and committed key files). Install `gitleaks` and run it too.
2. The demo JWT secret from the earlier version of this project was shown in a chat and is public knowledge: never reuse it. This version has no default secrets.
3. `.env` is **not** in git (`git ls-files .env` prints nothing). Remove `BOOTSTRAP_ADMIN_*` after the first start.
4. `REQUIRE_HTTPS=true` and `TRUSTED_PROXY_HOPS=1` (the prod override sets both). The gateway port must not be published directly in production.
5. Run `.\scripts\smoke-test.ps1` against the deployed URL (`-BaseUrl https://...`) and confirm the first-run admin can log in.
6. Schedule `scripts/backup.sh`; test a restore once.
