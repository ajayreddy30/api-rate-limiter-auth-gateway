package com.ratelimiter.apigateway.security;

import com.ratelimiter.apigateway.config.SecurityProperties;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/** Test helper: builds tokens the same way auth-service does, plus deliberately broken variants. */
public final class TestTokens {

    public static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 64 bytes
    public static final String ISSUER = "test-issuer";
    public static final String AUDIENCE = "test-audience";
    public static final String INTERNAL_KEY = "internal-key-internal-key-internal-key-123456";

    private TestTokens() {
    }

    public static SecurityProperties properties(boolean requireHttps, int trustedHops) {
        return new SecurityProperties(requireHttps, trustedHops, INTERNAL_KEY,
                new SecurityProperties.Jwt(SECRET, ISSUER, AUDIENCE));
    }

    public static SecretKey key(String secret) {
        return new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    public static JwtBuilder builder(String subject, String role, Instant expiresAt, String audience, String issuer) {
        JwtBuilder b = Jwts.builder()
                .issuer(issuer)
                .subject(subject)
                .audience().add(audience).and()
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(expiresAt.minusSeconds(900)))
                .expiration(Date.from(expiresAt));
        if (role != null) {
            b.claim("role", role);
        }
        return b;
    }

    public static String valid(String subject, String role) {
        return builder(subject, role, Instant.now().plusSeconds(900), AUDIENCE, ISSUER)
                .signWith(key(SECRET), Jwts.SIG.HS256).compact();
    }
}
