package com.ratelimiter.productservice.dto;

import java.math.BigDecimal;
import java.time.Instant;

public record ProductResponse(Long id, String name, BigDecimal price, String owner, Instant createdAt) {
}
