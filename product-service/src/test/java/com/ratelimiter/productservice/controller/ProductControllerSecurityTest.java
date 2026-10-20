package com.ratelimiter.productservice.controller;

import com.ratelimiter.productservice.dto.ProductResponse;
import com.ratelimiter.productservice.exception.GlobalExceptionHandler;
import com.ratelimiter.productservice.security.InternalAuthFilter;
import com.ratelimiter.productservice.service.ProductService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ProductControllerSecurityTest {

    private static final String KEY = "internal-key-internal-key-internal-key-123456";

    private ProductService service;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        service = mock(ProductService.class);
        mvc = MockMvcBuilders.standaloneSetup(new ProductController(service))
                .setControllerAdvice(new GlobalExceptionHandler())
                .addFilters(new InternalAuthFilter(KEY))
                .build();
    }

    private static MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder b, String user, String role) {
        return b.header("X-Internal-Key", KEY).header("X-User-Name", user).header("X-User-Role", role);
    }

    @Test
    void callsWithoutTheGatewayKeyAreRefused() throws Exception {
        mvc.perform(get("/products").header("X-User-Name", "alice").header("X-User-Role", "ADMIN"))
                .andExpect(status().isForbidden());
    }

    @Test
    void anyKnownRoleCanListProducts() throws Exception {
        when(service.list(0, 50)).thenReturn(List.of(
                new ProductResponse(1L, "Laptop", new BigDecimal("999.99"), "alice", Instant.now())));
        mvc.perform(as(get("/products"), "bob", "CUSTOMER"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").value("Laptop"));
    }

    @Test
    void unknownRoleIsRefused() throws Exception {
        mvc.perform(as(get("/products"), "bob", "SUPERUSER")).andExpect(status().isForbidden());
    }

    @Test
    void customerCannotCreateProducts() throws Exception {
        mvc.perform(as(post("/products"), "bob", "CUSTOMER")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Phone\",\"price\":499.99}"))
                .andExpect(status().isForbidden());
        verify(service, never()).create(any(), any());
    }

    @Test
    void sellerCanCreateProducts() throws Exception {
        when(service.create(any(), eq("sam"))).thenReturn(
                new ProductResponse(7L, "Phone", new BigDecimal("499.99"), "sam", Instant.now()));
        mvc.perform(as(post("/products"), "sam", "SELLER")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Phone\",\"price\":499.99}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.owner").value("sam"));
    }

    @Test
    void markupInProductNameIsRejected() throws Exception {
        mvc.perform(as(post("/products"), "sam", "SELLER")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"<script>alert(1)</script>\",\"price\":5}"))
                .andExpect(status().isBadRequest());
        verify(service, never()).create(any(), any());
    }

    @Test
    void invalidPricesAreRejected() throws Exception {
        for (String price : new String[] {"-1", "0", "1000001", "1.234"}) {
            mvc.perform(as(post("/products"), "sam", "SELLER")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"name\":\"Phone\",\"price\":" + price + "}"))
                    .andExpect(status().isBadRequest());
        }
    }

    @Test
    void nonNumericIdIsA400() throws Exception {
        mvc.perform(as(get("/products/abc"), "bob", "CUSTOMER")).andExpect(status().isBadRequest());
    }
}
