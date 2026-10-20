package com.ratelimiter.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record RoleUpdateRequest(@NotBlank(message = "role is required") String role) {
}
