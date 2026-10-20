package com.ratelimiter.authservice.controller;

import com.ratelimiter.authservice.dto.UserSummary;
import com.ratelimiter.authservice.exception.GlobalExceptionHandler;
import com.ratelimiter.authservice.security.InternalAuthFilter;
import com.ratelimiter.authservice.service.AdminUserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AdminUserControllerSecurityTest {

    private static final String KEY = "internal-key-internal-key-internal-key-123456";

    private AdminUserService service;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        service = mock(AdminUserService.class);
        mvc = MockMvcBuilders.standaloneSetup(new AdminUserController(service))
                .setControllerAdvice(new GlobalExceptionHandler())
                .addFilters(new InternalAuthFilter(KEY))
                .build();
    }

    @Test
    void requestWithoutInternalKeyIsRefused() throws Exception {
        mvc.perform(get("/auth/admin/users")
                        .header("X-User-Name", "root").header("X-User-Role", "ADMIN"))
                .andExpect(status().isForbidden());
    }

    @Test
    void requestWithWrongInternalKeyIsRefused() throws Exception {
        mvc.perform(get("/auth/admin/users").header("X-Internal-Key", "wrong-key-wrong-key-wrong-key-wrong-key")
                        .header("X-User-Name", "root").header("X-User-Role", "ADMIN"))
                .andExpect(status().isForbidden());
    }

    @Test
    void customerCannotListUsers() throws Exception {
        mvc.perform(get("/auth/admin/users").header("X-Internal-Key", KEY)
                        .header("X-User-Name", "bob").header("X-User-Role", "CUSTOMER"))
                .andExpect(status().isForbidden())
                .andExpect(content().json("{\"error\":\"Forbidden\"}"));
    }

    @Test
    void sellerCannotChangeRoles() throws Exception {
        mvc.perform(put("/auth/admin/users/bob/role").header("X-Internal-Key", KEY)
                        .header("X-User-Name", "sam").header("X-User-Role", "SELLER")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCanListUsers() throws Exception {
        when(service.list(0, 50)).thenReturn(List.of(new UserSummary("alice", "CUSTOMER", false)));
        mvc.perform(get("/auth/admin/users").header("X-Internal-Key", KEY)
                        .header("X-User-Name", "root").header("X-User-Role", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("alice"))
                .andExpect(jsonPath("$[0].password").doesNotExist())
                .andExpect(jsonPath("$[0].passwordHash").doesNotExist());
    }

    @Test
    void malformedBodyIsA400WithoutInternals() throws Exception {
        mvc.perform(put("/auth/admin/users/bob/role").header("X-Internal-Key", KEY)
                        .header("X-User-Name", "root").header("X-User-Role", "ADMIN")
                        .contentType(MediaType.APPLICATION_JSON).content("{not json"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Exception"))));
    }
}
