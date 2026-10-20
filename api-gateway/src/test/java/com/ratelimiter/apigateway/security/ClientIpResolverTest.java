package com.ratelimiter.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpResolverTest {

    private static MockServerHttpRequest request(String xff) {
        MockServerHttpRequest.BaseBuilder<?> b = MockServerHttpRequest.get("/products")
                .remoteAddress(new InetSocketAddress("10.0.0.5", 5555));
        if (xff != null) {
            b.header("X-Forwarded-For", xff);
        }
        return b.build();
    }

    @Test
    void withoutTrustedProxiesForwardedHeaderIsIgnored() {
        ClientIpResolver resolver = new ClientIpResolver(TestTokens.properties(false, 0));
        assertThat(resolver.resolve(request("1.2.3.4"))).isEqualTo("10.0.0.5");
    }

    @Test
    void oneTrustedProxyUsesTheLastEntryAndIgnoresClientSuppliedOnes() {
        ClientIpResolver resolver = new ClientIpResolver(TestTokens.properties(false, 1));
        // "6.6.6.6" was forged by the client; the proxy appended the address it actually saw.
        assertThat(resolver.resolve(request("6.6.6.6, 203.0.113.9"))).isEqualTo("203.0.113.9");
    }

    @Test
    void twoTrustedProxiesUseTheSecondFromTheEnd() {
        ClientIpResolver resolver = new ClientIpResolver(TestTokens.properties(false, 2));
        assertThat(resolver.resolve(request("6.6.6.6, 203.0.113.9, 172.18.0.2"))).isEqualTo("203.0.113.9");
    }

    @Test
    void fallsBackToPeerWhenHeaderMissingTooShortOrNotAnIp() {
        ClientIpResolver resolver = new ClientIpResolver(TestTokens.properties(false, 2));
        assertThat(resolver.resolve(request(null))).isEqualTo("10.0.0.5");
        assertThat(resolver.resolve(request("203.0.113.9"))).isEqualTo("10.0.0.5");

        ClientIpResolver one = new ClientIpResolver(TestTokens.properties(false, 1));
        assertThat(one.resolve(request("not an ip; DROP"))).isEqualTo("10.0.0.5");
    }
}
