package com.ratelimiter.apigateway.filter;

import com.ratelimiter.apigateway.config.SecurityProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * When security.require-https is on, plain-HTTP requests are refused (not redirected, which avoids open-redirect
 * issues). "Secure" means TLS terminated by the gateway itself, or - only when a trusted proxy is configured - an
 * X-Forwarded-Proto: https header set by that proxy.
 */
@Component
public class HttpsEnforcementFilter implements GlobalFilter, Ordered {

    private final boolean requireHttps;
    private final int trustedHops;

    public HttpsEnforcementFilter(SecurityProperties properties) {
        this.requireHttps = properties.requireHttps();
        this.trustedHops = properties.trustedProxyHops();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!requireHttps || isSecure(exchange.getRequest())) {
            return chain.filter(exchange);
        }
        return GatewayResponses.error(exchange, HttpStatus.FORBIDDEN, "HTTPS required");
    }

    private boolean isSecure(ServerHttpRequest request) {
        if (request.getSslInfo() != null) {
            return true;
        }
        if (trustedHops <= 0) {
            return false;
        }
        List<String> values = request.getHeaders().get("X-Forwarded-Proto");
        if (values == null || values.isEmpty()) {
            return false;
        }
        String[] parts = values.get(values.size() - 1).split(",");
        return "https".equalsIgnoreCase(parts[parts.length - 1].trim());
    }

    @Override
    public int getOrder() {
        return -350;
    }
}
