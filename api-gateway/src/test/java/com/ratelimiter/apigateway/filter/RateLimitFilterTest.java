package com.ratelimiter.apigateway.filter;

import com.ratelimiter.apigateway.config.RateLimitProperties;
import com.ratelimiter.apigateway.config.RateLimitProperties.Tier;
import com.ratelimiter.apigateway.ratelimit.RateLimitResult;
import com.ratelimiter.apigateway.ratelimit.RateTier;
import com.ratelimiter.apigateway.ratelimit.TokenBucketRateLimiter;
import com.ratelimiter.apigateway.security.AuthenticatedUser;
import com.ratelimiter.apigateway.security.ClientIpResolver;
import com.ratelimiter.apigateway.security.Role;
import com.ratelimiter.apigateway.security.RoutePolicy;
import com.ratelimiter.apigateway.security.TestTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RateLimitFilterTest {

    private final RoutePolicy policy = new RoutePolicy();
    private TokenBucketRateLimiter limiter;
    private RateLimitFilter filter;
    private GatewayFilterChain chain;

    @BeforeEach
    void setUp() {
        limiter = mock(TokenBucketRateLimiter.class);
        RateLimitProperties props = new RateLimitProperties(300, Map.of(
                "login", new Tier(10, 10, 60, false),
                "register", new Tier(10, 10, 600, false),
                "read", new Tier(60, 60, 60, true),
                "write", new Tier(20, 20, 60, true)));
        filter = new RateLimitFilter(limiter, props, new ClientIpResolver(TestTokens.properties(false, 0)));
        chain = FilterTestSupport.chain();
    }

    private MockServerWebExchange exchange(HttpMethod method, String path, AuthenticatedUser user) {
        MockServerWebExchange ex = FilterTestSupport.exchange(method.name(), "http://localhost" + path, null);
        ex.getAttributes().put(GatewayAttributes.RULE, policy.decide(method, path).rule());
        if (user != null) {
            ex.getAttributes().put(GatewayAttributes.PRINCIPAL, user);
        }
        return ex;
    }

    @Test
    void allowedRequestPassesAndReportsRemainingTokens() {
        when(limiter.tryConsume(any(), eq(RateTier.READ))).thenReturn(Mono.just(new RateLimitResult(true, 41, 0, false)));
        MockServerWebExchange ex = exchange(HttpMethod.GET, "/products", new AuthenticatedUser("alice", Role.CUSTOMER));

        filter.filter(ex, chain).block();

        verify(chain).filter(any());
        assertThat(ex.getResponse().getHeaders().getFirst("X-RateLimit-Remaining")).isEqualTo("41");
        assertThat(ex.getResponse().getHeaders().getFirst("X-RateLimit-Limit")).isEqualTo("60");
    }

    @Test
    void authenticatedRequestsAreKeyedByVerifiedUsername() {
        when(limiter.tryConsume(any(), any())).thenReturn(Mono.just(new RateLimitResult(true, 1, 0, false)));
        filter.filter(exchange(HttpMethod.GET, "/products", new AuthenticatedUser("alice", Role.CUSTOMER)), chain).block();

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(limiter).tryConsume(key.capture(), eq(RateTier.READ));
        assertThat(key.getValue()).isEqualTo("rl:read:user:alice");
    }

    @Test
    void anonymousLoginIsKeyedByClientIp() {
        when(limiter.tryConsume(any(), any())).thenReturn(Mono.just(new RateLimitResult(true, 1, 0, false)));
        filter.filter(exchange(HttpMethod.POST, "/auth/login", null), chain).block();

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(limiter).tryConsume(key.capture(), eq(RateTier.LOGIN));
        assertThat(key.getValue()).isEqualTo("rl:login:ip:203.0.113.9");
    }

    @Test
    void exceededLimitReturns429WithRetryAfterAndStopsTheChain() {
        when(limiter.tryConsume(any(), any())).thenReturn(Mono.just(new RateLimitResult(false, 0, 7, false)));
        MockServerWebExchange ex = exchange(HttpMethod.POST, "/auth/login", null);

        filter.filter(ex, chain).block();

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(ex.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("7");
        verify(chain, never()).filter(any());
    }

    @Test
    void redisFailureOnLoginFailsClosedWith503() {
        when(limiter.tryConsume(any(), any())).thenReturn(Mono.just(RateLimitResult.unavailable()));
        MockServerWebExchange ex = exchange(HttpMethod.POST, "/auth/login", null);

        filter.filter(ex, chain).block();

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        verify(chain, never()).filter(any());
    }

    @Test
    void redisFailureOnReadTierFailsOpen() {
        when(limiter.tryConsume(any(), any())).thenReturn(Mono.just(RateLimitResult.unavailable()));
        MockServerWebExchange ex = exchange(HttpMethod.GET, "/products", new AuthenticatedUser("alice", Role.CUSTOMER));

        filter.filter(ex, chain).block();

        verify(chain).filter(any());
    }
}
