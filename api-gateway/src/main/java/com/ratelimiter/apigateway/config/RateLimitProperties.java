package com.ratelimiter.apigateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

/**
 * @param redisTimeoutMs how long to wait for Redis before treating the limiter as unavailable
 * @param tiers          token bucket settings by tier name (login, register, read, write)
 */
@ConfigurationProperties(prefix = "rate-limit")
public record RateLimitProperties(long redisTimeoutMs, Map<String, Tier> tiers) {

    /**
     * @param capacity            maximum tokens (largest allowed burst)
     * @param refillTokens        tokens added per period
     * @param refillPeriodSeconds length of one refill period
     * @param failOpen            if Redis is unavailable: true = let the request through, false = refuse it (503)
     */
    public record Tier(long capacity, long refillTokens, long refillPeriodSeconds, boolean failOpen) {
    }
}
