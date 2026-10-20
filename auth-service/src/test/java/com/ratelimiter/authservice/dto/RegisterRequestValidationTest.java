package com.ratelimiter.authservice.dto;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RegisterRequestValidationTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void acceptsValidInput() {
        assertThat(validator.validate(new RegisterRequest("alice_01", "Str0ngPassw0rd"))).isEmpty();
    }

    @Test
    void rejectsWeakPasswords() {
        assertThat(validator.validate(new RegisterRequest("alice", "Sh0rt"))).isNotEmpty();
        assertThat(validator.validate(new RegisterRequest("alice", "onlylettersnodigits"))).isNotEmpty();
        assertThat(validator.validate(new RegisterRequest("alice", "1234567890123"))).isNotEmpty();
        assertThat(validator.validate(new RegisterRequest("alice", "A1" + "x".repeat(71)))).isNotEmpty();
    }

    @Test
    void rejectsUnsafeOrMalformedUsernames() {
        assertThat(validator.validate(new RegisterRequest("<script>", "Str0ngPassw0rd"))).isNotEmpty();
        assertThat(validator.validate(new RegisterRequest("a b", "Str0ngPassw0rd"))).isNotEmpty();
        assertThat(validator.validate(new RegisterRequest("ab", "Str0ngPassw0rd"))).isNotEmpty();
        assertThat(validator.validate(new RegisterRequest("a".repeat(33), "Str0ngPassw0rd"))).isNotEmpty();
        assertThat(validator.validate(new RegisterRequest("", "Str0ngPassw0rd"))).isNotEmpty();
        assertThat(validator.validate(new RegisterRequest(null, null))).isNotEmpty();
    }
}
