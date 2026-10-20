package com.ratelimiter.apigateway.filter;

import com.ratelimiter.apigateway.security.AuthenticatedUser;
import com.ratelimiter.apigateway.security.InvalidTokenException;
import com.ratelimiter.apigateway.security.JwtValidator;
import com.ratelimiter.apigateway.security.RoutePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Centralised authentication and authorisation:
 * 1) refuse unsafe paths, 2) look the request up in the route allow-list (404/405 if absent),
 * 3) for protected routes verify the JWT, 4) check the caller's role against the route's allowed roles.
 */
@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationFilter.class);
    private static final String BEARER = "Bearer ";

    private final RoutePolicy policy;
    private final JwtValidator validator;

    public AuthenticationFilter(RoutePolicy policy, JwtValidator validator) {
        this.policy = policy;
        this.validator = validator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getRawPath();

        if (!RoutePolicy.isSafePath(path)) {
            return GatewayResponses.error(exchange, HttpStatus.BAD_REQUEST, "Bad request");
        }

        RoutePolicy.Decision decision = policy.decide(request.getMethod(), path);
        switch (decision.outcome()) {
            case NOT_FOUND:
                return GatewayResponses.error(exchange, HttpStatus.NOT_FOUND, "Not found");
            case METHOD_NOT_ALLOWED:
                exchange.getResponse().getHeaders().setAllow(decision.allowedMethods());
                return GatewayResponses.error(exchange, HttpStatus.METHOD_NOT_ALLOWED, "Method not allowed");
            default:
                break;
        }

        RoutePolicy.Rule rule = decision.rule();
        exchange.getAttributes().put(GatewayAttributes.RULE, rule);

        if (rule.isPublic()) {
            return chain.filter(exchange);
        }

        Optional<String> token = extractBearerToken(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
        if (token.isEmpty()) {
            return unauthorized(exchange);
        }

        AuthenticatedUser user;
        try {
            user = validator.validate(token.get());
        } catch (InvalidTokenException e) {
            // Reason goes to the log only. The token itself is never logged.
            log.warn("AUTH_REJECTED reason={} method={} path={}", e.getMessage(), request.getMethod(), path);
            return unauthorized(exchange);
        }

        if (!rule.roles().contains(user.role())) {
            log.warn("AUTHZ_DENIED user={} role={} method={} path={}", user.username(), user.role(),
                    request.getMethod(), path);
            return GatewayResponses.error(exchange, HttpStatus.FORBIDDEN, "Forbidden");
        }

        exchange.getAttributes().put(GatewayAttributes.PRINCIPAL, user);
        return chain.filter(exchange);
    }

    private static Optional<String> extractBearerToken(String header) {
        if (header == null || header.length() <= BEARER.length() || header.length() > 2100) {
            return Optional.empty();
        }
        if (!header.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return Optional.empty();
        }
        String token = header.substring(BEARER.length()).trim();
        if (token.isEmpty() || token.indexOf(' ') >= 0) {
            return Optional.empty();
        }
        return Optional.of(token);
    }

    private static Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        return GatewayResponses.error(exchange, HttpStatus.UNAUTHORIZED, "Authentication required");
    }

    @Override
    public int getOrder() {
        return -200;
    }
}
