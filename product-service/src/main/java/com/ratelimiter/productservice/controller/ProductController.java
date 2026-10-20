package com.ratelimiter.productservice.controller;

import com.ratelimiter.productservice.dto.ProductRequest;
import com.ratelimiter.productservice.dto.ProductResponse;
import com.ratelimiter.productservice.exception.ApiException;
import com.ratelimiter.productservice.model.Role;
import com.ratelimiter.productservice.service.ProductService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * X-User-Name / X-User-Role are set by the gateway after it validated the JWT. They can be trusted because
 * InternalAuthFilter only lets requests that carry the gateway's secret key reach this controller.
 */
@RestController
@RequestMapping("/products")
public class ProductController {

    private final ProductService service;

    public ProductController(ProductService service) {
        this.service = service;
    }

    @GetMapping
    public List<ProductResponse> list(@RequestHeader("X-User-Role") String roleHeader,
                                      @RequestParam(defaultValue = "0") int page,
                                      @RequestParam(defaultValue = "50") int size) {
        roleOf(roleHeader); // any known role may read
        return service.list(Math.max(page, 0), Math.min(Math.max(size, 1), 100));
    }

    @GetMapping("/{id}")
    public ProductResponse get(@PathVariable Long id, @RequestHeader("X-User-Role") String roleHeader) {
        roleOf(roleHeader);
        return service.get(id);
    }

    @PostMapping
    public ResponseEntity<ProductResponse> create(@Valid @RequestBody ProductRequest request,
                                                  @RequestHeader("X-User-Name") String username,
                                                  @RequestHeader("X-User-Role") String roleHeader) {
        Role role = roleOf(roleHeader);
        if (role != Role.ADMIN && role != Role.SELLER) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Forbidden");
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(request, username));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id,
                                       @RequestHeader("X-User-Name") String username,
                                       @RequestHeader("X-User-Role") String roleHeader) {
        service.delete(id, username, roleOf(roleHeader));
        return ResponseEntity.noContent().build();
    }

    private static Role roleOf(String header) {
        return Role.parse(header).orElseThrow(() -> new ApiException(HttpStatus.FORBIDDEN, "Forbidden"));
    }
}
