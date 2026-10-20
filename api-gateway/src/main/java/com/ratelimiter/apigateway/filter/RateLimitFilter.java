package com.ratelimiter.apigateway.filter;

import com.ratelimiter.apigateway.config.RateLimitProperties;
import com.ratelimiter.apigateway.ratelimit.RateLimitResult;
import com.ratelimiter.apigateway.ratelimit.RateTier;
import com.ratelimiter.apigateway.ratelimit.TokenBucketRateLimiter;
import com.ratelimiter.apigateway.security.AuthenticatedUser;
import com.ratelimiter.apigateway.security.ClientIpResolver;
import com.ratelimiter.apigateway.security.RoutePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Per-client token bucket. The identity is trustworthy by construction:
 * - authenticated routes: the username from the already-verified JWT (never a client-supplied header);
 * - public routes (login/register): the client IP from {@link ClientIpResolver}.
 * Runs after authentication, so invalid tokens never consume a user's tokens.
 */
@Component
public class RateLimitFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private final TokenBucketRateLimiter limiter;
    private final RateLimitProperties properties;
    private final ClientIpResolver ipResolver;

    public RateLimitFilter(TokenBucketRateLimiter limiter, RateLimitProperties properties, ClientIpResolver ipResolver) {
        this.limiter = limiter;
        this.properties = properties;
        this.ipResolver = ipResolver;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        RoutePolicy.Rule rule = exchange.getAttribute(GatewayAttributes.RULE);
        if (rule == null) {
            // Cannot happen: AuthenticationFilter always sets the rule before this filter runs.
            return GatewayResponses.error(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "Internal error");
        }

        AuthenticatedUser user = exchange.getAttribute(GatewayAttributes.PRINCIPAL);
        String identity = user != null
                ? "user:" + user.username()
                : "ip:" + ipResolver.resolve(exchange.getRequest());
        RateTier tier = rule.tier();
        String key = "rl:" + tier.key() + ":" + identity;

        return limiter.tryConsume(key, tier).flatMap(result -> handle(exchange, chain, tier, identity, result));
    }

    private Mono<Void> handle(ServerWebExchange exchange, GatewayFilterChain chain, RateTier tier,
                              String identity, RateLimitResult result) {
        RateLimitProperties.Tier cfg = properties.tiers().get(tier.key());

        if (result.backendFailure()) {
            if (cfg.failOpen()) {
                log.error("RATE_LIMIT_UNAVAILABLE tier={} policy=fail-open (request allowed)", tier.key());
                return chain.filter(exchange);
            }
            log.error("RATE_LIMIT_UNAVAILABLE tier={} policy=fail-closed (request refused)", tier.key());
            exchange.getResponse().getHeaders().set("Retry-After", "5");
            return GatewayResponses.error(exchange, HttpStatus.SERVICE_UNAVAILABLE, "Service temporarily unavailable");
        }

        exchange.getResponse().getHeaders().set("X-RateLimit-Limit", Long.toString(cfg.capacity()));
        exchange.getResponse().getHeaders().set("X-RateLimit-Remaining", Long.toString(result.remaining()));

        if (result.allowed()) {
            return chain.filter(exchange);
        }

        log.warn("RATE_LIMITED tier={} identity={} retryAfterSeconds={}", tier.key(), identity, result.retryAfterSeconds());
        exchange.getResponse().getHeaders().set("Retry-After", Long.toString(result.retryAfterSeconds()));
        return GatewayResponses.error(exchange, HttpStatus.TOO_MANY_REQUESTS, "Too many requests");
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
