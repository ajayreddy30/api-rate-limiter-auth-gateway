package com.ratelimiter.authservice.service;

import com.ratelimiter.authservice.dto.TokenResponse;
import com.ratelimiter.authservice.exception.ApiException;
import com.ratelimiter.authservice.model.Role;
import com.ratelimiter.authservice.model.User;
import com.ratelimiter.authservice.repository.UserRepository;
import com.ratelimiter.authservice.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final String GOOD_PASSWORD = "Correct-Horse-9";

    private final PasswordEncoder encoder = new BCryptPasswordEncoder(4); // low cost: tests only
    private UserRepository users;
    private MutableClock clock;
    private AuthService service;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        when(users.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        service = new AuthService(users, encoder, new JwtService(SECRET, "iss", "aud", 15), clock);
    }

    @Test
    void registrationAlwaysCreatesCustomerWithBcryptHash() {
        when(users.existsByUsername("alice")).thenReturn(false);

        service.register("Alice", GOOD_PASSWORD);

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(users).save(saved.capture());
        User user = saved.getValue();
        assertThat(user.getUsername()).isEqualTo("alice");
        assertThat(user.getRole()).isEqualTo(Role.CUSTOMER);
        assertThat(user.getPasswordHash()).startsWith("$2").isNotEqualTo(GOOD_PASSWORD);
        assertThat(encoder.matches(GOOD_PASSWORD, user.getPasswordHash())).isTrue();
    }

    @Test
    void duplicateUsernameIsConflict() {
        when(users.existsByUsername("alice")).thenReturn(true);
        assertThatThrownBy(() -> service.register("alice", GOOD_PASSWORD))
                .isInstanceOfSatisfying(ApiException.class,
                        e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.CONFLICT));
    }

    @Test
    void passwordContainingUsernameIsRejected() {
        assertThatThrownBy(() -> service.register("alice", "alice-Password-1"))
                .isInstanceOfSatisfying(ApiException.class,
                        e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    void passwordLongerThan72BytesIsRejectedNotTruncated() {
        String tooLong = "A1" + "x".repeat(71);
        assertThatThrownBy(() -> service.register("bob", tooLong)).isInstanceOf(ApiException.class);
    }

    @Test
    void successfulLoginReturnsTokenAndClearsFailures() {
        User user = storedUser("alice", Role.SELLER);
        user.recordFailure(clock.instant(), 5, Duration.ofMinutes(15));
        when(users.findByUsernameForUpdate("alice")).thenReturn(Optional.of(user));

        Optional<TokenResponse> result = service.login("ALICE", GOOD_PASSWORD);

        assertThat(result).isPresent();
        assertThat(result.get().accessToken()).isNotBlank();
        assertThat(result.get().role()).isEqualTo("SELLER");
        assertThat(user.getFailedAttempts()).isZero();
    }

    @Test
    void unknownUserAndWrongPasswordBothJustReturnEmpty() {
        when(users.findByUsernameForUpdate("ghost")).thenReturn(Optional.empty());
        assertThat(service.login("ghost", GOOD_PASSWORD)).isEmpty();

        User user = storedUser("alice", Role.CUSTOMER);
        when(users.findByUsernameForUpdate("alice")).thenReturn(Optional.of(user));
        assertThat(service.login("alice", "Wrong-Password-1")).isEmpty();
        assertThat(user.getFailedAttempts()).isEqualTo(1);
    }

    @Test
    void fiveFailuresLockTheAccountEvenAgainstTheCorrectPassword() {
        User user = storedUser("alice", Role.CUSTOMER);
        when(users.findByUsernameForUpdate("alice")).thenReturn(Optional.of(user));

        for (int i = 0; i < 5; i++) {
            assertThat(service.login("alice", "Wrong-Password-1")).isEmpty();
        }
        assertThat(user.getLockedUntil()).isNotNull();
        assertThat(service.login("alice", GOOD_PASSWORD)).isEmpty();
    }

    @Test
    void lockExpiresAfterFifteenMinutes() {
        User user = storedUser("alice", Role.CUSTOMER);
        when(users.findByUsernameForUpdate("alice")).thenReturn(Optional.of(user));
        for (int i = 0; i < 5; i++) {
            service.login("alice", "Wrong-Password-1");
        }
        assertThat(service.login("alice", GOOD_PASSWORD)).isEmpty();

        clock.advance(Duration.ofMinutes(16));

        assertThat(service.login("alice", GOOD_PASSWORD)).isPresent();
        assertThat(user.getFailedAttempts()).isZero();
    }

    private User storedUser(String username, Role role) {
        return new User(username, encoder.encode(GOOD_PASSWORD), role, clock.instant());
    }

    /** Minimal controllable clock. */
    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
