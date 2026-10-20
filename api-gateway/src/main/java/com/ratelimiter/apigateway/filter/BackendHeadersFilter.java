package com.ratelimiter.apigateway.filter;

import com.ratelimiter.apigateway.config.SecurityProperties;
import com.ratelimiter.apigateway.security.AuthenticatedUser;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * Last step before proxying. Adds the internal key (proves to the backend that the request came through the
 * gateway) and the verified identity, and removes credentials the backends do not need: the JWT itself and cookies.
 */
@Component
public class BackendHeadersFilter implements GlobalFilter, Ordered {

    private final String internalKey;

    public BackendHeadersFilter(SecurityProperties properties) {
        String key = properties.internalApiKey();
        if (key == null || key.getBytes(StandardCharsets.UTF_8).length < 32 || key.startsWith("CHANGE_ME")) {
            throw new IllegalStateException(
                    "INTERNAL_API_KEY must be a random value of at least 32 bytes (run scripts/generate-env)");
        }
        this.internalKey = key;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        AuthenticatedUser user = exchange.getAttribute(GatewayAttributes.PRINCIPAL);
        ServerHttpRequest forwarded = exchange.getRequest().mutate()
                .headers(h -> {
                    h.remove(HttpHeaders.AUTHORIZATION);
                    h.remove(HttpHeaders.COOKIE);
                    h.set("X-Internal-Key", internalKey);
                    if (user != null) {
                        h.set("X-User-Name", user.username());
                        h.set("X-User-Role", user.role().name());
                    }
                })
                .build();
        return chain.filter(exchange.mutate().request(forwarded).build());
    }

    @Override
    public int getOrder() {
        return -50;
    }
}
