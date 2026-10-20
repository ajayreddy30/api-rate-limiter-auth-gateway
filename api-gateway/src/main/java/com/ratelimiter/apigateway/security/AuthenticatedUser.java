package com.ratelimiter.apigateway.security;

public record AuthenticatedUser(String username, Role role) {
}
