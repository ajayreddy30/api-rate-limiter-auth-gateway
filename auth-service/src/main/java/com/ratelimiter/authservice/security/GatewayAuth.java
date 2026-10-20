package com.ratelimiter.authservice.security;

import com.ratelimiter.authservice.exception.ApiException;
import com.ratelimiter.authservice.model.Role;
import org.springframework.http.HttpStatus;

/** Server-side role check based on the headers the gateway sets after validating the JWT. */
public final class GatewayAuth {

    private GatewayAuth() {
    }

    public static void requireAdmin(String roleHeader) {
        if (!Role.ADMIN.name().equals(roleHeader)) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Forbidden");
        }
    }
}
