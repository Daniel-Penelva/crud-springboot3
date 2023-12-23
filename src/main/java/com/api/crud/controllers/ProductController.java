package com.api.crud.controllers;

import com.api.crud.domain.Product;
import com.api.crud.domain.RequestProductDto;
import com.api.crud.repository.ProductRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/product")
public class ProductController {

    @Autowired
    private ProductRepository productRepository;

    // localhost:8080/product
    @GetMapping
    public ResponseEntity getAllProducts() {
        var allProducts = productRepository.findAll();
        return ResponseEntity.ok(allProducts);
    }

    // localhost:8080/product/create
    @PostMapping("/create")
    public ResponseEntity registerProduct(@RequestBody @Valid RequestProductDto data){
        Product newProduct = new Product(data);
        productRepository.save(newProduct);
        return ResponseEntity.ok().body("Product created successfully!");
        // ou // return ResponseEntity.ok().build();
    }
}
