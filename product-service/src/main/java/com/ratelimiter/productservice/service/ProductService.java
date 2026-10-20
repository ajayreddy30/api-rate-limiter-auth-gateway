package com.ratelimiter.productservice.service;

import com.ratelimiter.productservice.dto.ProductRequest;
import com.ratelimiter.productservice.dto.ProductResponse;
import com.ratelimiter.productservice.exception.ApiException;
import com.ratelimiter.productservice.model.Product;
import com.ratelimiter.productservice.model.Role;
import com.ratelimiter.productservice.repository.ProductRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;

@Service
public class ProductService {

    private static final Logger log = LoggerFactory.getLogger(ProductService.class);

    private final ProductRepository products;
    private final Clock clock;

    public ProductService(ProductRepository products, Clock clock) {
        this.products = products;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<ProductResponse> list(int page, int size) {
        return products.findAll(PageRequest.of(page, size, Sort.by("id"))).stream()
                .map(ProductService::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public ProductResponse get(Long id) {
        return products.findById(id).map(ProductService::toResponse)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Product not found"));
    }

    @Transactional
    public ProductResponse create(ProductRequest request, String ownerUsername) {
        Product saved = products.save(
                new Product(request.name().trim(), request.price(), ownerUsername, clock.instant()));
        log.info("AUDIT event=PRODUCT_CREATED id={} owner={}", saved.getId(), ownerUsername);
        return toResponse(saved);
    }

    /**
     * Object-level authorization: an ADMIN may delete any product, a SELLER only their own, everyone else nothing.
     * (The gateway already limits this route to ADMIN/SELLER; this check is what stops a seller deleting
     * someone else's product by guessing ids.)
     */
    @Transactional
    public void delete(Long id, String callerUsername, Role callerRole) {
        Product product = products.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Product not found"));
        boolean allowed = callerRole == Role.ADMIN
                || (callerRole == Role.SELLER && product.getOwnerUsername().equals(callerUsername));
        if (!allowed) {
            log.warn("AUDIT event=PRODUCT_DELETE_DENIED id={} actor={} role={}", id, callerUsername, callerRole);
            throw new ApiException(HttpStatus.FORBIDDEN, "Forbidden");
        }
        products.delete(product);
        log.info("AUDIT event=PRODUCT_DELETED id={} actor={}", id, callerUsername);
    }

    private static ProductResponse toResponse(Product p) {
        return new ProductResponse(p.getId(), p.getName(), p.getPrice(), p.getOwnerUsername(), p.getCreatedAt());
    }
}
