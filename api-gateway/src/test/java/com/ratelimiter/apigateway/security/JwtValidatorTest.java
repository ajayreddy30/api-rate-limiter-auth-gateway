package com.ratelimiter.apigateway.security;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static com.ratelimiter.apigateway.security.TestTokens.AUDIENCE;
import static com.ratelimiter.apigateway.security.TestTokens.ISSUER;
import static com.ratelimiter.apigateway.security.TestTokens.SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtValidatorTest {

    private final JwtValidator validator = new JwtValidator(TestTokens.properties(false, 0));

    private void assertRejected(String token) {
        assertThatThrownBy(() -> validator.validate(token)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void acceptsAWellFormedToken() throws Exception {
        AuthenticatedUser user = validator.validate(TestTokens.valid("alice", "CUSTOMER"));
        assertThat(user.username()).isEqualTo("alice");
        assertThat(user.role()).isEqualTo(Role.CUSTOMER);
    }

    @Test
    void rejectsExpiredToken() {
        String token = TestTokens.builder("alice", "CUSTOMER", Instant.now().minusSeconds(3600), AUDIENCE, ISSUER)
                .signWith(TestTokens.key(SECRET), Jwts.SIG.HS256).compact();
        assertRejected(token);
    }

    @Test
    void rejectsTokenSignedWithAnotherSecret() {
        String token = TestTokens.builder("alice", "ADMIN", Instant.now().plusSeconds(900), AUDIENCE, ISSUER)
                .signWith(TestTokens.key("another-secret-another-secret-another-secret-0000"), Jwts.SIG.HS256).compact();
        assertRejected(token);
    }

    @Test
    void rejectsTamperedPayloadWithOriginalSignature() {
        String[] parts = TestTokens.valid("alice", "CUSTOMER").split("\\.");
        String forgedPayload = "{\"iss\":\"" + ISSUER + "\",\"sub\":\"alice\",\"aud\":\"" + AUDIENCE
                + "\",\"role\":\"ADMIN\",\"iat\":" + Instant.now().getEpochSecond()
                + ",\"exp\":" + (Instant.now().getEpochSecond() + 900) + "}";
        String forged = parts[0] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(forgedPayload.getBytes(StandardCharsets.UTF_8))
                + "." + parts[2];
        assertRejected(forged);
    }

    @Test
    void rejectsUnsignedAlgNoneToken() {
        String token = TestTokens.builder("alice", "ADMIN", Instant.now().plusSeconds(900), AUDIENCE, ISSUER).compact();
        assertRejected(token);
    }

    @Test
    void rejectsOtherHmacAlgorithmEvenWithTheCorrectSecret() {
        String token = TestTokens.builder("alice", "CUSTOMER", Instant.now().plusSeconds(900), AUDIENCE, ISSUER)
                .signWith(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA512"), Jwts.SIG.HS512)
                .compact();
        assertRejected(token);
    }

    @Test
    void rejectsWrongIssuerAndWrongAudience() {
        assertRejected(TestTokens.builder("alice", "CUSTOMER", Instant.now().plusSeconds(900), AUDIENCE, "evil-issuer")
                .signWith(TestTokens.key(SECRET), Jwts.SIG.HS256).compact());
        assertRejected(TestTokens.builder("alice", "CUSTOMER", Instant.now().plusSeconds(900), "other-api", ISSUER)
                .signWith(TestTokens.key(SECRET), Jwts.SIG.HS256).compact());
    }

    @Test
    void rejectsMissingOrUnknownRole() {
        assertRejected(TestTokens.valid("alice", null));
        assertRejected(TestTokens.valid("alice", "SUPERUSER"));
    }

    @Test
    void rejectsSubjectThatIsNotAValidUsername() {
        assertRejected(TestTokens.valid("Robert'); DROP TABLE users;--", "CUSTOMER"));
    }

    @Test
    void rejectsGarbageEmptyAndOversizedInput() {
        assertRejected("not.a.jwt");
        assertRejected("");
        assertRejected(null);
        assertRejected("a".repeat(3000));
    }

    @Test
    void refusesToStartWithWeakSecret() {
        var weak = new com.ratelimiter.apigateway.config.SecurityProperties(false, 0, TestTokens.INTERNAL_KEY,
                new com.ratelimiter.apigateway.config.SecurityProperties.Jwt("too-short", ISSUER, AUDIENCE));
        assertThatThrownBy(() -> new JwtValidator(weak))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageNotContaining("too-short");
    }
}
