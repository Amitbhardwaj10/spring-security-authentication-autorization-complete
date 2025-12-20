package com.amit.security.controller;

import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/products")
public class ProductController {

    private record Product(Integer productId, String productName, Double price) {}

    List<Product> products = new ArrayList<>(List.of(
            new Product(1, "Iphone", 999.0),
            new Product(2, "Mac Pro", 2099.0)
    ));

    @GetMapping
    public List<Product> getProducts() {
        return products;
    }

    @PostMapping
    public Product saveProduct(@RequestBody Product product) {
        products.add(product);
        return product;
    }
}
