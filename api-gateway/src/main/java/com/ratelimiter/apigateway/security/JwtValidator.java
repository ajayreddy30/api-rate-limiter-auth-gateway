package com.ratelimiter.apigateway.security;

import com.ratelimiter.apigateway.config.SecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Verifies the signature and every claim the gateway relies on:
 * signature (HS256 only), issuer, audience, expiry (30 s clock skew), subject format and role.
 */
@Component
public class JwtValidator {

    private static final int MAX_TOKEN_LENGTH = 2048;
    private static final Pattern USERNAME = Pattern.compile("^[a-z0-9_.-]{3,32}$");

    private final JwtParser parser;
    private final String audience;

    public JwtValidator(SecurityProperties properties) {
        SecurityProperties.Jwt jwt = properties.jwt();
        String secret = jwt == null ? null : jwt.secret();
        byte[] bytes = secret == null ? new byte[0] : secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32 || secret.startsWith("CHANGE_ME")) {
            // Never include the value in the message.
            throw new IllegalStateException(
                    "JWT_SECRET must be a random value of at least 32 bytes (run scripts/generate-env)");
        }
        SecretKey key = new SecretKeySpec(bytes, "HmacSHA256");
        this.audience = jwt.audience();
        this.parser = Jwts.parser()
                .verifyWith(key)
                .requireIssuer(jwt.issuer())
                .clockSkewSeconds(30)
                .build();
    }

    public AuthenticatedUser validate(String token) throws InvalidTokenException {
        if (token == null || token.isBlank() || token.length() > MAX_TOKEN_LENGTH) {
            throw new InvalidTokenException("token missing or too long");
        }
        try {
            // parseSignedClaims rejects unsigned ("alg":"none") and encrypted tokens and checks the signature.
            Jws<Claims> jws = parser.parseSignedClaims(token);

            // Algorithm pinning: only HS256 is accepted, even though a stronger HMAC would verify with this key.
            if (!"HS256".equals(jws.getHeader().getAlgorithm())) {
                throw new InvalidTokenException("unexpected signing algorithm");
            }

            Claims claims = jws.getPayload();
            Set<String> audiences = claims.getAudience();
            if (audiences == null || !audiences.contains(audience)) {
                throw new InvalidTokenException("wrong audience");
            }
            if (claims.getExpiration() == null || claims.getIssuedAt() == null) {
                throw new InvalidTokenException("missing exp/iat");
            }
            String subject = claims.getSubject();
            if (subject == null || !USERNAME.matcher(subject).matches()) {
                throw new InvalidTokenException("invalid subject");
            }
            Role role = Role.parse(claims.get("role", String.class))
                    .orElseThrow(() -> new InvalidTokenException("invalid or missing role"));
            return new AuthenticatedUser(subject, role);
        } catch (JwtException | IllegalArgumentException e) {
            // Expired, malformed, bad signature, wrong issuer, unsupported ... all look the same to the client.
            throw new InvalidTokenException(e.getClass().getSimpleName(), e);
        }
    }
}
