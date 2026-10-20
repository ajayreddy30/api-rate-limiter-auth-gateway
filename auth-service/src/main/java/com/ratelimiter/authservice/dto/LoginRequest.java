package com.ratelimiter.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "username is required")
        @Size(max = 64, message = "username is too long")
        String username,

        @NotBlank(message = "password is required")
        @Size(max = 128, message = "password is too long")
        String password) {
}
