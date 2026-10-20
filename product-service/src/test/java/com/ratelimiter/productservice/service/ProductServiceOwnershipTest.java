package com.ratelimiter.productservice.service;

import com.ratelimiter.productservice.exception.ApiException;
import com.ratelimiter.productservice.model.Product;
import com.ratelimiter.productservice.model.Role;
import com.ratelimiter.productservice.repository.ProductRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ProductServiceOwnershipTest {

    private ProductRepository repo;
    private ProductService service;
    private Product aliceProduct;

    @BeforeEach
    void setUp() {
        repo = mock(ProductRepository.class);
        service = new ProductService(repo, Clock.systemUTC());
        aliceProduct = new Product("Laptop", new BigDecimal("999.99"), "alice", Instant.now());
        when(repo.findById(1L)).thenReturn(Optional.of(aliceProduct));
    }

    @Test
    void sellerCanDeleteOwnProduct() {
        service.delete(1L, "alice", Role.SELLER);
        verify(repo).delete(aliceProduct);
    }

    @Test
    void sellerCannotDeleteSomeoneElsesProduct() {
        assertThatThrownBy(() -> service.delete(1L, "mallory", Role.SELLER))
                .isInstanceOfSatisfying(ApiException.class, e -> org.assertj.core.api.Assertions
                        .assertThat(e.getStatus()).isEqualTo(HttpStatus.FORBIDDEN));
        verify(repo, never()).delete(aliceProduct);
    }

    @Test
    void adminCanDeleteAnyProduct() {
        service.delete(1L, "root", Role.ADMIN);
        verify(repo).delete(aliceProduct);
    }

    @Test
    void customerCanNeverDelete() {
        assertThatThrownBy(() -> service.delete(1L, "alice", Role.CUSTOMER)).isInstanceOf(ApiException.class);
        verify(repo, never()).delete(aliceProduct);
    }

    @Test
    void missingProductIsNotFound() {
        when(repo.findById(99L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.delete(99L, "root", Role.ADMIN))
                .isInstanceOfSatisfying(ApiException.class, e -> org.assertj.core.api.Assertions
                        .assertThat(e.getStatus()).isEqualTo(HttpStatus.NOT_FOUND));
    }
}
