package com.ratelimiter.authservice.bootstrap;

import com.ratelimiter.authservice.exception.ApiException;
import com.ratelimiter.authservice.model.Role;
import com.ratelimiter.authservice.repository.UserRepository;
import com.ratelimiter.authservice.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * Creates the first ADMIN from environment variables if (and only if) that username does not exist yet.
 * Remove BOOTSTRAP_ADMIN_* from the environment after the first successful start.
 */
@Component
public class AdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final AuthService authService;
    private final UserRepository users;
    private final String username;
    private final String password;

    public AdminBootstrap(AuthService authService, UserRepository users,
                          @Value("${bootstrap.admin.username:}") String username,
                          @Value("${bootstrap.admin.password:}") String password) {
        this.authService = authService;
        this.users = users;
        this.username = username;
        this.password = password;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (username.isBlank() || password.isBlank()) {
            return;
        }
        String normalized = username.trim().toLowerCase(Locale.ROOT);
        if (users.existsByUsername(normalized)) {
            log.info("Bootstrap admin '{}' already exists - nothing to do. Remove BOOTSTRAP_ADMIN_* from the environment.", normalized);
            return;
        }
        try {
            authService.createUser(username, password, Role.ADMIN);
            log.warn("Bootstrap admin '{}' created. Remove BOOTSTRAP_ADMIN_* from the environment now.", normalized);
        } catch (ApiException e) {
            // The message is one of our fixed, password-free validation messages.
            log.error("Bootstrap admin was NOT created: {}", e.getMessage());
        }
    }
}
