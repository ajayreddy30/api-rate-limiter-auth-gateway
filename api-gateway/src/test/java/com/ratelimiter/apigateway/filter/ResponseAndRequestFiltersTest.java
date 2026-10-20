package com.ratelimiter.apigateway.filter;

import com.ratelimiter.apigateway.security.AuthenticatedUser;
import com.ratelimiter.apigateway.security.Role;
import com.ratelimiter.apigateway.security.TestTokens;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ResponseAndRequestFiltersTest {

    @Test
    void securityHeadersAreAddedToEveryResponseIncludingHstsWhenHttpsIsRequired() {
        SecurityHeadersFilter filter = new SecurityHeadersFilter(TestTokens.properties(true, 1));
        MockServerWebExchange ex = FilterTestSupport.exchange("GET", "http://localhost/products", null);
        ex.getResponse().getHeaders().set("Server", "leaky/1.0");

        filter.filter(ex, FilterTestSupport.chain()).block();
        ex.getResponse().setComplete().block();

        var h = ex.getResponse().getHeaders();
        assertThat(h.getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(h.getFirst("X-Frame-Options")).isEqualTo("DENY");
        assertThat(h.getFirst("Content-Security-Policy")).contains("default-src 'none'");
        assertThat(h.getFirst("Strict-Transport-Security")).contains("max-age=31536000");
        assertThat(h.getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(h.containsKey("Server")).isFalse();
    }

    @Test
    void httpsEnforcementRefusesPlainHttp() {
        HttpsEnforcementFilter filter = new HttpsEnforcementFilter(TestTokens.properties(true, 0));
        MockServerWebExchange ex = FilterTestSupport.exchange("GET", "http://localhost/products", null);
        GatewayFilterChain chain = FilterTestSupport.chain();

        filter.filter(ex, chain).block();

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        verify(chain, never()).filter(any());
    }

    @Test
    void forwardedProtoIsIgnoredWithoutATrustedProxy() {
        HttpsEnforcementFilter filter = new HttpsEnforcementFilter(TestTokens.properties(true, 0));
        MockServerWebExchange ex = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost/products")
                .header("X-Forwarded-Proto", "https").build());

        filter.filter(ex, FilterTestSupport.chain()).block();

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void forwardedProtoHttpsIsAcceptedBehindATrustedProxy() {
        HttpsEnforcementFilter filter = new HttpsEnforcementFilter(TestTokens.properties(true, 1));
        MockServerWebExchange ex = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost/products")
                .header("X-Forwarded-Proto", "https").build());
        GatewayFilterChain chain = FilterTestSupport.chain();

        filter.filter(ex, chain).block();

        verify(chain).filter(any());
    }

    @Test
    void httpsEnforcementCanBeSwitchedOffForLocalTesting() {
        HttpsEnforcementFilter filter = new HttpsEnforcementFilter(TestTokens.properties(false, 0));
        GatewayFilterChain chain = FilterTestSupport.chain();

        filter.filter(FilterTestSupport.exchange("GET", "http://localhost/products", null), chain).block();

        verify(chain).filter(any());
    }

    @Test
    void clientSuppliedIdentityHeadersAreStripped() {
        RequestSanitizingFilter filter = new RequestSanitizingFilter();
        MockServerWebExchange ex = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost/products")
                .header("X-User-Role", "ADMIN").header("X-User-Name", "root")
                .header("X-Internal-Key", "guess").build());
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        filter.filter(ex, chain).block();

        ArgumentCaptor<ServerWebExchange> forwarded = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(forwarded.capture());
        var headers = forwarded.getValue().getRequest().getHeaders();
        assertThat(headers.containsKey("X-User-Role")).isFalse();
        assertThat(headers.containsKey("X-User-Name")).isFalse();
        assertThat(headers.containsKey("X-Internal-Key")).isFalse();
        assertThat(headers.getFirst("X-Request-Id")).isNotBlank();
    }

    @Test
    void backendsReceiveVerifiedIdentityAndInternalKeyButNotTheJwt() {
        BackendHeadersFilter filter = new BackendHeadersFilter(TestTokens.properties(false, 0));
        MockServerWebExchange ex = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost/products")
                .header("Authorization", "Bearer secret-token").header("Cookie", "a=b").build());
        ex.getAttributes().put(GatewayAttributes.PRINCIPAL, new AuthenticatedUser("alice", Role.SELLER));
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        filter.filter(ex, chain).block();

        ArgumentCaptor<ServerWebExchange> forwarded = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(forwarded.capture());
        var headers = forwarded.getValue().getRequest().getHeaders();
        assertThat(headers.getFirst("X-User-Name")).isEqualTo("alice");
        assertThat(headers.getFirst("X-User-Role")).isEqualTo("SELLER");
        assertThat(headers.getFirst("X-Internal-Key")).isEqualTo(TestTokens.INTERNAL_KEY);
        assertThat(headers.containsKey("Authorization")).isFalse();
        assertThat(headers.containsKey("Cookie")).isFalse();
    }
}
