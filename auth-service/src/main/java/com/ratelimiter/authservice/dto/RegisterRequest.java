package com.ratelimiter.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** There is deliberately no "role" field: self-registration always creates a CUSTOMER. */
public record RegisterRequest(
        @NotBlank(message = "username is required")
        @Pattern(regexp = "^[A-Za-z0-9_.-]{3,32}$",
                message = "username must be 3-32 characters: letters, digits, underscore, dot or hyphen")
        String username,

        @NotBlank(message = "password is required")
        @Size(min = 10, max = 72, message = "password must be 10-72 characters")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).+$",
                message = "password must contain at least one letter and one digit")
        String password) {
}
