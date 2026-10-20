package com.ratelimiter.apigateway.ratelimit;

public record RateLimitResult(boolean allowed, long remaining, long retryAfterSeconds, boolean backendFailure) {

    public static RateLimitResult unavailable() {
        return new RateLimitResult(false, 0, 0, true);
    }
}
