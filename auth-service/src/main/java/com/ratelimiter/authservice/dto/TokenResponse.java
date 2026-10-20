package com.ratelimiter.authservice.dto;

public record TokenResponse(String accessToken, String tokenType, long expiresInSeconds, String username, String role) {
}
