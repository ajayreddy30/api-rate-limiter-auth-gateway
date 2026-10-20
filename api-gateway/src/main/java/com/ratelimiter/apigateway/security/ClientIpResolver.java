package com.ratelimiter.apigateway.security;

import com.ratelimiter.apigateway.config.SecurityProperties;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Determines the client IP used as the rate-limit identity for anonymous requests.
 * <p>
 * X-Forwarded-For is trivially forgeable, so it is ignored unless {@code security.trusted-proxy-hops} says that
 * N trusted proxies sit in front of the gateway. Each trusted proxy appends the address it saw, so the client is
 * the entry N positions from the END of the list; anything to its left was supplied by the client and is ignored.
 */
@Component
public class ClientIpResolver {

    private static final Pattern IP_LITERAL = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");

    private final int trustedHops;

    public ClientIpResolver(SecurityProperties properties) {
        this.trustedHops = properties.trustedProxyHops();
    }

    public String resolve(ServerHttpRequest request) {
        String peer = peerAddress(request);
        if (trustedHops <= 0) {
            return peer;
        }
        List<String> forwarded = new ArrayList<>();
        List<String> headerValues = request.getHeaders().get("X-Forwarded-For");
        if (headerValues != null) {
            for (String value : headerValues) {
                for (String part : value.split(",")) {
                    String trimmed = part.trim();
                    if (!trimmed.isEmpty()) {
                        forwarded.add(trimmed);
                    }
                }
            }
        }
        if (forwarded.size() < trustedHops) {
            return peer;
        }
        String candidate = forwarded.get(forwarded.size() - trustedHops);
        return IP_LITERAL.matcher(candidate).matches() ? candidate : peer;
    }

    private static String peerAddress(ServerHttpRequest request) {
        InetSocketAddress remote = request.getRemoteAddress();
        if (remote == null || remote.getAddress() == null) {
            return "unknown";
        }
        return remote.getAddress().getHostAddress();
    }
}
