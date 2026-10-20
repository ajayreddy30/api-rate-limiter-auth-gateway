package com.ratelimiter.apigateway.security;

import com.ratelimiter.apigateway.ratelimit.RateTier;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

import static org.assertj.core.api.Assertions.assertThat;

class RoutePolicyTest {

    private final RoutePolicy policy = new RoutePolicy();

    @Test
    void loginAndRegisterArePublicAndUseTheirOwnTiers() {
        RoutePolicy.Decision login = policy.decide(HttpMethod.POST, "/auth/login");
        assertThat(login.outcome()).isEqualTo(RoutePolicy.Outcome.MATCH);
        assertThat(login.rule().isPublic()).isTrue();
        assertThat(login.rule().tier()).isEqualTo(RateTier.LOGIN);
        assertThat(policy.decide(HttpMethod.POST, "/auth/register").rule().tier()).isEqualTo(RateTier.REGISTER);
    }

    @Test
    void adminRoutesRequireAdminOnly() {
        assertThat(policy.decide(HttpMethod.GET, "/auth/admin/users").rule().roles()).containsExactly(Role.ADMIN);
        assertThat(policy.decide(HttpMethod.PUT, "/auth/admin/users/bob/role").rule().roles()).containsExactly(Role.ADMIN);
    }

    @Test
    void productWritesRequireAdminOrSeller() {
        assertThat(policy.decide(HttpMethod.POST, "/products").rule().roles())
                .containsExactlyInAnyOrder(Role.ADMIN, Role.SELLER);
        assertThat(policy.decide(HttpMethod.DELETE, "/products/5").rule().roles())
                .containsExactlyInAnyOrder(Role.ADMIN, Role.SELLER);
        assertThat(policy.decide(HttpMethod.GET, "/products/5").rule().roles())
                .containsExactlyInAnyOrder(Role.ADMIN, Role.SELLER, Role.CUSTOMER);
    }

    @Test
    void unknownPathsAreNotFoundAndWrongMethodsAreNotAllowed() {
        assertThat(policy.decide(HttpMethod.GET, "/actuator/health").outcome()).isEqualTo(RoutePolicy.Outcome.NOT_FOUND);
        assertThat(policy.decide(HttpMethod.GET, "/auth/admin").outcome()).isEqualTo(RoutePolicy.Outcome.NOT_FOUND);
        assertThat(policy.decide(HttpMethod.GET, "/products/").outcome()).isEqualTo(RoutePolicy.Outcome.NOT_FOUND);

        RoutePolicy.Decision wrongMethod = policy.decide(HttpMethod.PUT, "/products/5");
        assertThat(wrongMethod.outcome()).isEqualTo(RoutePolicy.Outcome.METHOD_NOT_ALLOWED);
        assertThat(wrongMethod.allowedMethods()).contains(HttpMethod.GET, HttpMethod.DELETE);
        assertThat(policy.decide(HttpMethod.GET, "/auth/login").outcome()).isEqualTo(RoutePolicy.Outcome.METHOD_NOT_ALLOWED);
    }

    @Test
    void pathGuardRejectsTraversalEncodingAndOddCharacters() {
        assertThat(RoutePolicy.isSafePath("/products/5")).isTrue();
        assertThat(RoutePolicy.isSafePath("/auth/admin/users/john.doe-1/role")).isTrue();

        assertThat(RoutePolicy.isSafePath("/products/../auth/admin/users")).isFalse();
        assertThat(RoutePolicy.isSafePath("/products/./5")).isFalse();
        assertThat(RoutePolicy.isSafePath("/products/%2e%2e/auth")).isFalse();
        assertThat(RoutePolicy.isSafePath("/products/%2F")).isFalse();
        assertThat(RoutePolicy.isSafePath("//products")).isFalse();
        assertThat(RoutePolicy.isSafePath("/products;jsessionid=1")).isFalse();
        assertThat(RoutePolicy.isSafePath("/products/a b")).isFalse();
        assertThat(RoutePolicy.isSafePath("/products\\5")).isFalse();
        assertThat(RoutePolicy.isSafePath("/" + "a".repeat(250))).isFalse();
        assertThat(RoutePolicy.isSafePath("products")).isFalse();
        assertThat(RoutePolicy.isSafePath(null)).isFalse();
    }
}
