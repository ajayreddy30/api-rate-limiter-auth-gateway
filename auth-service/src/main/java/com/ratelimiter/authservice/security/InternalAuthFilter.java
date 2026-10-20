package com.ratelimiter.authservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Only the gateway may call this service. The gateway adds a secret X-Internal-Key header to every
 * proxied request; anything without the correct key is refused. This is defence in depth on top of
 * network isolation, and it is what makes the X-User-* headers trustworthy.
 */
@Component
public class InternalAuthFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Internal-Key";

    private final byte[] expected;

    public InternalAuthFilter(@Value("${security.internal-api-key}") String key) {
        byte[] bytes = key == null ? new byte[0] : key.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32 || key.startsWith("CHANGE_ME")) {
            throw new IllegalStateException(
                    "INTERNAL_API_KEY must be a random value of at least 32 bytes (run scripts/generate-env)");
        }
        this.expected = bytes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String presented = request.getHeader(HEADER);
        boolean ok = presented != null
                && MessageDigest.isEqual(expected, presented.getBytes(StandardCharsets.UTF_8));
        if (!ok) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Forbidden\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
