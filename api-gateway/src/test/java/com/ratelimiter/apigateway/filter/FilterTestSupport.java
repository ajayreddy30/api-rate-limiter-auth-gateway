package com.ratelimiter.apigateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class FilterTestSupport {

    private FilterTestSupport() {
    }

    static GatewayFilterChain chain() {
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());
        return chain;
    }

    static MockServerWebExchange exchange(String method, String url, String bearerToken) {
        MockServerHttpRequest.BaseBuilder<?> b = MockServerHttpRequest.method(
                        org.springframework.http.HttpMethod.valueOf(method), url)
                .remoteAddress(new InetSocketAddress("203.0.113.9", 4444));
        if (bearerToken != null) {
            b.header("Authorization", "Bearer " + bearerToken);
        }
        return MockServerWebExchange.from(b.build());
    }
}
