package com.ratelimiter.authservice.controller;

import com.ratelimiter.authservice.dto.RoleUpdateRequest;
import com.ratelimiter.authservice.dto.UserSummary;
import com.ratelimiter.authservice.security.GatewayAuth;
import com.ratelimiter.authservice.service.AdminUserService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin-only routes. The gateway already requires the ADMIN role; this controller checks it again
 * (the X-User-* headers are trustworthy because InternalAuthFilter only admits the gateway).
 */
@RestController
@RequestMapping("/auth/admin")
public class AdminUserController {

    private final AdminUserService adminUsers;

    public AdminUserController(AdminUserService adminUsers) {
        this.adminUsers = adminUsers;
    }

    @GetMapping("/users")
    public List<UserSummary> listUsers(@RequestHeader("X-User-Role") String role,
                                       @RequestParam(defaultValue = "0") int page,
                                       @RequestParam(defaultValue = "50") int size) {
        GatewayAuth.requireAdmin(role);
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 100);
        return adminUsers.list(safePage, safeSize);
    }

    @PutMapping("/users/{username}/role")
    public UserSummary updateRole(@PathVariable String username,
                                  @Valid @RequestBody RoleUpdateRequest body,
                                  @RequestHeader("X-User-Name") String caller,
                                  @RequestHeader("X-User-Role") String role) {
        GatewayAuth.requireAdmin(role);
        return adminUsers.changeRole(caller, username, body.role());
    }
}
