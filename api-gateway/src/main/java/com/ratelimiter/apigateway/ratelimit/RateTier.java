package com.ratelimiter.apigateway.ratelimit;

import java.util.Locale;

/** Each tier has its own bucket settings in application.yml (rate-limit.tiers.*). */
public enum RateTier {
    LOGIN, REGISTER, READ, WRITE;

    public String key() {
        return name().toLowerCase(Locale.ROOT);
    }
}
