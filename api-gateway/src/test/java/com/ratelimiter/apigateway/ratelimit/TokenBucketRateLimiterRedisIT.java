package com.ratelimiter.apigateway.ratelimit;

import com.ratelimiter.apigateway.config.RateLimitProperties;
import com.ratelimiter.apigateway.config.RateLimitProperties.Tier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.ReactiveRedisConnection;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Flux;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs against a REAL Redis (the Lua script cannot be exercised any other way). It is skipped automatically when no
 * Redis is reachable. Configure with TEST_REDIS_HOST (default localhost), TEST_REDIS_PORT (default 6379) and
 * TEST_REDIS_PASSWORD (optional). scripts/load-env.ps1 sets the password for you.
 */
class TokenBucketRateLimiterRedisIT {

    private static LettuceConnectionFactory factory;
    private static ReactiveStringRedisTemplate template;

    @BeforeAll
    static void connect() {
        String host = System.getenv().getOrDefault("TEST_REDIS_HOST", "localhost");
        int port = Integer.parseInt(System.getenv().getOrDefault("TEST_REDIS_PORT", "6379"));
        String password = System.getenv("TEST_REDIS_PASSWORD");

        RedisStandaloneConfiguration cfg = new RedisStandaloneConfiguration(host, port);
        if (password != null && !password.isBlank()) {
            cfg.setPassword(RedisPassword.of(password));
        }
        factory = new LettuceConnectionFactory(cfg);
        factory.afterPropertiesSet();
        template = new ReactiveStringRedisTemplate(factory);

        boolean reachable;
        try {
            ReactiveRedisConnection connection = factory.getReactiveConnection();
            reachable = "PONG".equals(connection.ping().block(Duration.ofSeconds(2)));
            connection.close();
        } catch (Exception e) {
            reachable = false;
        }
        Assumptions.assumeTrue(reachable, "Redis not reachable - integration test skipped");
    }

    @AfterAll
    static void disconnect() {
        if (factory != null) {
            factory.destroy();
        }
    }

    private static TokenBucketRateLimiter limiter(long capacity, long refillTokens, long periodSeconds) {
        Tier tier = new Tier(capacity, refillTokens, periodSeconds, false);
        return new TokenBucketRateLimiter(template,
                new RateLimitProperties(1000, Map.of("login", tier, "register", tier, "read", tier, "write", tier)));
    }

    private static String freshKey() {
        return "it:" + UUID.randomUUID();
    }

    @Test
    void allowsExactlyCapacityRequestsThenRefuses() {
        TokenBucketRateLimiter limiter = limiter(5, 5, 3600);
        String key = freshKey();

        for (int i = 0; i < 5; i++) {
            assertThat(limiter.tryConsume(key, RateTier.READ).block().allowed()).as("request %d", i + 1).isTrue();
        }
        RateLimitResult sixth = limiter.tryConsume(key, RateTier.READ).block();
        assertThat(sixth.allowed()).isFalse();
        assertThat(sixth.backendFailure()).isFalse();
        assertThat(sixth.retryAfterSeconds()).isGreaterThanOrEqualTo(1);
    }

    @Test
    void concurrentRequestsCannotExceedCapacity() {
        TokenBucketRateLimiter limiter = limiter(10, 10, 3600);
        String key = freshKey();

        List<RateLimitResult> results = Flux.range(0, 200)
                .flatMap(i -> limiter.tryConsume(key, RateTier.READ), 100)
                .collectList()
                .block(Duration.ofSeconds(20));

        long allowed = results.stream().filter(RateLimitResult::allowed).count();
        assertThat(results).hasSize(200);
        assertThat(allowed).isEqualTo(10);
    }

    @Test
    void tokensRefillOverTime() throws Exception {
        TokenBucketRateLimiter limiter = limiter(2, 2, 1); // 2 tokens per second
        String key = freshKey();

        assertThat(limiter.tryConsume(key, RateTier.READ).block().allowed()).isTrue();
        assertThat(limiter.tryConsume(key, RateTier.READ).block().allowed()).isTrue();
        assertThat(limiter.tryConsume(key, RateTier.READ).block().allowed()).isFalse();

        Thread.sleep(1200);

        assertThat(limiter.tryConsume(key, RateTier.READ).block().allowed()).isTrue();
    }

    @Test
    void differentClientsHaveIndependentBuckets() {
        TokenBucketRateLimiter limiter = limiter(1, 1, 3600);
        String a = freshKey();
        String b = freshKey();

        assertThat(limiter.tryConsume(a, RateTier.READ).block().allowed()).isTrue();
        assertThat(limiter.tryConsume(a, RateTier.READ).block().allowed()).isFalse();
        assertThat(limiter.tryConsume(b, RateTier.READ).block().allowed()).isTrue();
    }
}
