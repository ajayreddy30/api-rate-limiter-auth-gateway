package com.ratelimiter.apigateway.ratelimit;

import com.ratelimiter.apigateway.config.RateLimitProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;

/**
 * Redis-backed token bucket. All state lives in Redis and is updated by one Lua script, so the check-and-take is
 * atomic and shared by every gateway instance. Nothing here blocks: the call is fully reactive.
 */
@Component
public class TokenBucketRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(TokenBucketRateLimiter.class);

    private final ReactiveStringRedisTemplate redis;
    private final RateLimitProperties properties;
    @SuppressWarnings("rawtypes")
    private final RedisScript<List> script;

    public TokenBucketRateLimiter(ReactiveStringRedisTemplate redis, RateLimitProperties properties) {
        this.redis = redis;
        this.properties = properties;

        if (properties.redisTimeoutMs() <= 0) {
            throw new IllegalStateException("rate-limit.redis-timeout-ms must be positive");
        }
        for (RateTier tier : RateTier.values()) {
            RateLimitProperties.Tier cfg = properties.tiers() == null ? null : properties.tiers().get(tier.key());
            if (cfg == null || cfg.capacity() <= 0 || cfg.refillTokens() <= 0 || cfg.refillPeriodSeconds() <= 0) {
                throw new IllegalStateException(
                        "rate-limit.tiers." + tier.key() + " must be configured with positive values");
            }
        }

        @SuppressWarnings("rawtypes")
        DefaultRedisScript<List> s = new DefaultRedisScript<>();
        s.setLocation(new ClassPathResource("scripts/token_bucket.lua"));
        s.setResultType(List.class);
        this.script = s;
    }

    /** Tries to take one token from the bucket stored under {@code key}. Never throws; Redis problems are reported in the result. */
    @SuppressWarnings({"rawtypes", "unchecked"})
    public Mono<RateLimitResult> tryConsume(String key, RateTier tier) {
        RateLimitProperties.Tier cfg = properties.tiers().get(tier.key());
        List<String> args = List.of(
                Long.toString(cfg.capacity()),
                Long.toString(cfg.refillTokens()),
                Long.toString(cfg.refillPeriodSeconds() * 1000L),
                "1");

        Flux<List> reply = redis.execute(script, List.of(key), args);
        return reply.next()
                .map(TokenBucketRateLimiter::parse)
                .timeout(Duration.ofMillis(properties.redisTimeoutMs()))
                .onErrorResume(ex -> {
                    log.error("Rate limiter backend failure: {}", ex.getClass().getSimpleName());
                    return Mono.just(RateLimitResult.unavailable());
                })
                .defaultIfEmpty(RateLimitResult.unavailable());
    }

    @SuppressWarnings("rawtypes")
    private static RateLimitResult parse(List reply) {
        boolean allowed = toLong(reply.get(0)) == 1L;
        long remaining = toLong(reply.get(1));
        long retryAfterMs = toLong(reply.get(2));
        long retryAfterSeconds = allowed ? 0 : Math.max(1, (retryAfterMs + 999) / 1000);
        return new RateLimitResult(allowed, remaining, retryAfterSeconds, false);
    }

    private static long toLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(String.valueOf(value));
    }
}
