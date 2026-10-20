package com.ratelimiter.productservice.model;

import java.util.Locale;
import java.util.Optional;

public enum Role {
    ADMIN, SELLER, CUSTOMER;

    public static Optional<Role> parse(String value) {
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(Role.valueOf(value.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
