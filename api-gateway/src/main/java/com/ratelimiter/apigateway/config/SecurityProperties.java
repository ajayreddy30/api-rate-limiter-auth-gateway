package com.ratelimiter.apigateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Security settings. Secrets come only from environment variables (see application.yml); there are no defaults.
 *
 * @param requireHttps       reject requests that did not arrive over HTTPS
 * @param trustedProxyHops   how many reverse proxies sit in front of the gateway (0 = none). Forwarded headers
 *                           are only believed when this is greater than 0.
 * @param internalApiKey     secret the gateway sends to backend services so they can tell it apart from other callers
 */
@ConfigurationProperties(prefix = "security")
public record SecurityProperties(boolean requireHttps, int trustedProxyHops, String internalApiKey, Jwt jwt) {

    public record Jwt(String secret, String issuer, String audience) {
    }
}
