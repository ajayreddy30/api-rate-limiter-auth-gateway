package com.ratelimiter.apigateway.filter;

import com.ratelimiter.apigateway.config.SecurityProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Adds security headers to EVERY response (including the gateway's own 401/403/429 and responses from backends),
 * and removes headers that reveal the technology in use.
 */
@Component
public class SecurityHeadersFilter implements GlobalFilter, Ordered {

    private final boolean hsts;

    public SecurityHeadersFilter(SecurityProperties properties) {
        this.hsts = properties.requireHttps();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Applied right before the response is committed, so it also covers responses written by other filters.
        exchange.getResponse().beforeCommit(() -> Mono.fromRunnable(() -> apply(exchange.getResponse().getHeaders())));
        return chain.filter(exchange);
    }

    private void apply(HttpHeaders headers) {
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        headers.set("Cache-Control", "no-store");
        if (hsts) {
            headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }
        headers.remove("Server");
        headers.remove("X-Powered-By");
    }

    @Override
    public int getOrder() {
        return -400;
    }
}
