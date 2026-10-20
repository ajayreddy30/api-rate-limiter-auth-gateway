package com.ratelimiter.authservice.security;

import com.ratelimiter.authservice.model.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    @Test
    void issuesHs256TokenWithExpectedClaimsAndFifteenMinuteLifetime() {
        JwtService service = new JwtService(SECRET, "iss", "aud", 15);
        String token = service.issue("alice", Role.SELLER);

        SecretKey key = new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        Jws<Claims> jws = Jwts.parser().verifyWith(key).requireIssuer("iss").build().parseSignedClaims(token);
        Claims claims = jws.getPayload();

        assertThat(jws.getHeader().getAlgorithm()).isEqualTo("HS256");
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getAudience()).containsExactly("aud");
        assertThat(claims.get("role", String.class)).isEqualTo("SELLER");
        assertThat(claims.getId()).isNotBlank();
        long lifetimeSeconds = (claims.getExpiration().getTime() - claims.getIssuedAt().getTime()) / 1000;
        assertThat(lifetimeSeconds).isBetween(899L, 901L);
        assertThat(service.ttlSeconds()).isEqualTo(900L);
    }

    @Test
    void refusesToStartWithShortSecretAndDoesNotEchoIt() {
        assertThatThrownBy(() -> new JwtService("short-secret", "iss", "aud", 15))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageNotContaining("short-secret");
    }

    @Test
    void refusesPlaceholderSecret() {
        String placeholder = "CHANGE_ME" + "x".repeat(40);
        assertThatThrownBy(() -> new JwtService(placeholder, "iss", "aud", 15))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refusesUnreasonableLifetime() {
        assertThatThrownBy(() -> new JwtService(SECRET, "iss", "aud", 0)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new JwtService(SECRET, "iss", "aud", 100000)).isInstanceOf(IllegalStateException.class);
    }
}
