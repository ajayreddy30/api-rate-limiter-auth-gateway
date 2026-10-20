package com.ratelimiter.authservice.dto;

/** Admin view of a user. Never includes the password hash. */
public record UserSummary(String username, String role, boolean locked) {
}
