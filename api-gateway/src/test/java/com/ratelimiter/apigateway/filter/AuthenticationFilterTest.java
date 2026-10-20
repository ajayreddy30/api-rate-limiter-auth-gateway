package com.ratelimiter.apigateway.filter;

import com.ratelimiter.apigateway.security.AuthenticatedUser;
import com.ratelimiter.apigateway.security.JwtValidator;
import com.ratelimiter.apigateway.security.Role;
import com.ratelimiter.apigateway.security.RoutePolicy;
import com.ratelimiter.apigateway.security.TestTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class AuthenticationFilterTest {

    private AuthenticationFilter filter;
    private GatewayFilterChain chain;

    @BeforeEach
    void setUp() {
        filter = new AuthenticationFilter(new RoutePolicy(), new JwtValidator(TestTokens.properties(false, 0)));
        chain = FilterTestSupport.chain();
    }

    private MockServerWebExchange run(String method, String path, String token) {
        MockServerWebExchange exchange = FilterTestSupport.exchange(method, "http://localhost" + path, token);
        filter.filter(exchange, chain).block();
        return exchange;
    }

    @Test
    void publicLoginRouteNeedsNoToken() {
        MockServerWebExchange ex = run("POST", "/auth/login", null);
        verify(chain).filter(any());
        assertThat(ex.getAttributes()).containsKey(GatewayAttributes.RULE);
        assertThat(ex.getAttributes()).doesNotContainKey(GatewayAttributes.PRINCIPAL);
    }

    @Test
    void protectedRouteWithoutTokenIs401() {
        MockServerWebExchange ex = run("GET", "/products", null);
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isEqualTo("Bearer");
        verify(chain, never()).filter(any());
    }

    @Test
    void invalidTokenIs401AndErrorDoesNotRevealWhy() {
        MockServerWebExchange ex = run("GET", "/products", "garbage.token.value");
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ex.getResponse().getBodyAsString().block()).isEqualTo("{\"error\":\"Authentication required\"}");
        verify(chain, never()).filter(any());
    }

    @Test
    void customerCanReadButNotWriteProducts() {
        String token = TestTokens.valid("bob", "CUSTOMER");
        MockServerWebExchange read = run("GET", "/products", token);
        assertThat(read.getAttributes().get(GatewayAttributes.PRINCIPAL)).isEqualTo(new AuthenticatedUser("bob", Role.CUSTOMER));

        MockServerWebExchange write = run("POST", "/products", token);
        assertThat(write.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void sellerCanCreateProductsButNotUseAdminRoutes() {
        String token = TestTokens.valid("sam", "SELLER");
        assertThat(run("POST", "/products", token).getAttributes()).containsKey(GatewayAttributes.PRINCIPAL);
        assertThat(run("GET", "/auth/admin/users", token).getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void adminCanUseAdminRoutes() {
        String token = TestTokens.valid("root", "ADMIN");
        MockServerWebExchange ex = run("GET", "/auth/admin/users", token);
        assertThat(ex.getAttributes()).containsKey(GatewayAttributes.PRINCIPAL);
    }

    @Test
    void unknownRouteIs404AndWrongMethodIs405WithAllowHeader() {
        assertThat(run("GET", "/actuator/env", TestTokens.valid("root", "ADMIN")).getResponse().getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);

        MockServerWebExchange ex = run("PUT", "/products/5", TestTokens.valid("root", "ADMIN"));
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
        assertThat(ex.getResponse().getHeaders().getAllow()).contains(HttpMethod.GET, HttpMethod.DELETE);
    }

    @Test
    void traversalAndEncodedPathsAreRejectedBeforeAnyPolicyLookup() {
        assertThat(run("GET", "/products/../auth/admin/users", TestTokens.valid("root", "ADMIN"))
                .getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(run("GET", "/products/%2e%2e/x", TestTokens.valid("root", "ADMIN"))
                .getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void nonBearerAuthorizationSchemesAreRefused() {
        MockServerWebExchange basic = MockServerWebExchange.from(
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.get("http://localhost/products")
                        .header("Authorization", "Basic dXNlcjpwYXNz").build());

        filter.filter(basic, chain).block();

        assertThat(basic.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any());
    }
}
