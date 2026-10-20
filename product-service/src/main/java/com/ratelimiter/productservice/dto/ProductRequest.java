package com.ratelimiter.productservice.dto;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.math.BigDecimal;

/**
 * The name is restricted to an allow-list of characters, so markup such as "&lt;script&gt;" can never be stored.
 * (Clients must still HTML-encode data when rendering it - see SECURITY.md.)
 */
public record ProductRequest(
        @NotBlank(message = "name is required")
        @Size(max = 100, message = "name must be at most 100 characters")
        @Pattern(regexp = "^[\\p{L}\\p{N} .,'()\\-_/#+]+$",
                message = "name may contain letters, digits, spaces and . , ' ( ) - _ / # +")
        String name,

        @NotNull(message = "price is required")
        @DecimalMin(value = "0.01", message = "price must be at least 0.01")
        @DecimalMax(value = "1000000", message = "price must be at most 1000000")
        @Digits(integer = 7, fraction = 2, message = "price may have at most 2 decimal places")
        BigDecimal price) {
}
