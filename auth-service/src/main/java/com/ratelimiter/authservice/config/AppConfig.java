package com.ratelimiter.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;

@Configuration
public class AppConfig {

    /** BCrypt with a work factor of 12 (about 250 ms per hash on current hardware). Salt is generated per hash. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /** Injected so tests can control time (lock expiry). */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
