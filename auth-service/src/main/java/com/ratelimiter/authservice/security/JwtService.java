package com.ratelimiter.authservice.security;

import com.ratelimiter.authservice.model.Role;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/** Issues short-lived HS256 access tokens. The gateway validates them with the same secret. */
@Component
public class JwtService {

    private final SecretKey key;
    private final String issuer;
    private final String audience;
    private final Duration ttl;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.issuer}") String issuer,
                      @Value("${jwt.audience}") String audience,
                      @Value("${jwt.expiration-minutes}") long expirationMinutes) {
        byte[] bytes = secret == null ? new byte[0] : secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32 || secret.startsWith("CHANGE_ME")) {
            // Never include the value in the message.
            throw new IllegalStateException(
                    "JWT_SECRET must be a random value of at least 32 bytes (run scripts/generate-env)");
        }
        if (expirationMinutes < 1 || expirationMinutes > 1440) {
            throw new IllegalStateException("jwt.expiration-minutes must be between 1 and 1440");
        }
        this.key = new SecretKeySpec(bytes, "HmacSHA256");
        this.issuer = issuer;
        this.audience = audience;
        this.ttl = Duration.ofMinutes(expirationMinutes);
    }

    public String issue(String username, Role role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(issuer)
                .subject(username)
                .audience().add(audience).and()
                .claim("role", role.name())
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public long ttlSeconds() {
        return ttl.toSeconds();
    }
}
