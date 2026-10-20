package com.ratelimiter.authservice.service;

import com.ratelimiter.authservice.dto.TokenResponse;
import com.ratelimiter.authservice.exception.ApiException;
import com.ratelimiter.authservice.model.Role;
import com.ratelimiter.authservice.model.User;
import com.ratelimiter.authservice.repository.UserRepository;
import com.ratelimiter.authservice.security.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class AuthService {

    static final int MAX_FAILED_ATTEMPTS = 5;
    static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private static final Pattern USERNAME = Pattern.compile("^[a-z0-9_.-]{3,32}$");
    private static final Pattern HAS_LETTER = Pattern.compile(".*[A-Za-z].*");
    private static final Pattern HAS_DIGIT = Pattern.compile(".*\\d.*");

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final Clock clock;
    /** Compared against when the user does not exist, so "unknown user" and "wrong password" take equally long. */
    private final String dummyHash;

    public AuthService(UserRepository users, PasswordEncoder encoder, JwtService jwt, Clock clock) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
        this.clock = clock;
        this.dummyHash = encoder.encode("not-a-real-password-used-for-timing-equalisation");
    }

    /** Public self-registration: always creates a CUSTOMER. */
    public void register(String username, String password) {
        createUser(username, password, Role.CUSTOMER);
    }

    @Transactional
    public User createUser(String rawUsername, String rawPassword, Role role) {
        String username = normalize(rawUsername);
        if (!USERNAME.matcher(username).matches()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Invalid username");
        }
        validatePassword(username, rawPassword);
        if (users.existsByUsername(username)) {
            throw new ApiException(HttpStatus.CONFLICT, "Username is already taken");
        }
        User saved = users.save(new User(username, encoder.encode(rawPassword), role, clock.instant()));
        log.info("AUDIT event=USER_CREATED user={} role={}", username, role);
        return saved;
    }

    /**
     * Returns a token on success and an empty Optional on ANY failure (unknown user, wrong password or locked
     * account), so callers cannot tell the cases apart. The method returns instead of throwing so the failed-attempt
     * counter is committed.
     */
    @Transactional
    public Optional<TokenResponse> login(String rawUsername, String rawPassword) {
        String username = normalize(rawUsername);
        Instant now = clock.instant();

        Optional<User> found = users.findByUsernameForUpdate(username);
        if (found.isEmpty()) {
            encoder.matches(rawPassword, dummyHash);
            // The attempted name is attacker-controlled, so it is deliberately not logged.
            log.warn("AUDIT event=LOGIN_FAILURE reason=unknown_user");
            return Optional.empty();
        }

        User user = found.get();
        if (user.isLockExpired(now)) {
            user.clearFailures();
        }

        // Always verify the password (even for locked accounts) so response timing does not reveal lock state.
        boolean passwordOk = encoder.matches(rawPassword, user.getPasswordHash());

        if (user.isLocked(now)) {
            log.warn("AUDIT event=LOGIN_REJECTED reason=account_locked user={}", user.getUsername());
            return Optional.empty();
        }
        if (!passwordOk) {
            boolean lockedNow = user.recordFailure(now, MAX_FAILED_ATTEMPTS, LOCK_DURATION);
            log.warn("AUDIT event=LOGIN_FAILURE reason=bad_password user={} failedAttempts={}",
                    user.getUsername(), user.getFailedAttempts());
            if (lockedNow) {
                log.warn("AUDIT event=ACCOUNT_LOCKED user={} minutes={}", user.getUsername(), LOCK_DURATION.toMinutes());
            }
            return Optional.empty();
        }

        user.clearFailures();
        log.info("AUDIT event=LOGIN_SUCCESS user={}", user.getUsername());
        return Optional.of(new TokenResponse(jwt.issue(user.getUsername(), user.getRole()), "Bearer",
                jwt.ttlSeconds(), user.getUsername(), user.getRole().name()));
    }

    private void validatePassword(String username, String password) {
        if (password == null || password.length() < 10) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Password must be at least 10 characters");
        }
        // BCrypt only uses the first 72 BYTES; refuse longer input instead of silently truncating it.
        if (password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Password must be at most 72 bytes");
        }
        if (!HAS_LETTER.matcher(password).matches() || !HAS_DIGIT.matcher(password).matches()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Password must contain at least one letter and one digit");
        }
        if (password.toLowerCase(Locale.ROOT).contains(username)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Password must not contain the username");
        }
    }

    static String normalize(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }
}
