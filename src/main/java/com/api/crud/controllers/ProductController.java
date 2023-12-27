package com.api.crud.controllers;

import com.api.crud.domain.Product;
import com.api.crud.domain.RequestProductDto;
import com.api.crud.repository.ProductRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.UUID;

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

    // localhost:8080/product/all
    @GetMapping("/all")
    public ResponseEntity getAllProductsStatusTrue() {
        var allProducts = productRepository.findAllByActiveTrue();
        return ResponseEntity.ok(allProducts);
    }

    // localhost:8080/product/search/{id}
    @GetMapping("/search/{id}")
    public ResponseEntity findByIdProduct(@PathVariable String id){
        Product idProduct = productRepository.findById(id).orElseThrow(() -> new EntityNotFoundException("Product not found with id: " + id));
        return ResponseEntity.ok(idProduct);
    }

    // localhost:8080/product/create
    @PostMapping("/create")
    @Transactional
    public ResponseEntity registerProduct(@RequestBody @Valid RequestProductDto data) {
        Product newProduct = new Product(data);
        productRepository.save(newProduct);
        return ResponseEntity.ok().body("Product created successfully!");
        // ou // return ResponseEntity.ok().build();
    }

    // localhost:8080/product/update
    @PutMapping("/update")
    @Transactional
    public ResponseEntity updateProduct(@RequestBody @Valid RequestProductDto data) {

        Optional<Product> optionalProduct = productRepository.findById(data.id());

        if (optionalProduct.isPresent()) {
            Product updateProduct = optionalProduct.get();
            updateProduct.setName(data.name());
            updateProduct.setPrice_in_cents(data.price_in_cents());
            productRepository.save(updateProduct);
            return ResponseEntity.ok(updateProduct);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    // localhost:8080/product/replace
    @PutMapping("/replace")
    @Transactional
    public ResponseEntity updateProduct1(@RequestBody @Valid RequestProductDto data) {

        UUID productId = UUID.fromString(data.id());

        Product updateProduct1 = productRepository.findById(productId.toString())
                .orElseThrow(() -> new EntityNotFoundException("Product not found with id: " + productId));

        updateProduct1.setName(data.name());
        updateProduct1.setPrice_in_cents(data.price_in_cents());

        productRepository.save(updateProduct1);
        return ResponseEntity.ok(updateProduct1);
    }

    // localhost:8080/product/delete/{id}
    @DeleteMapping("delete/{id}")
    @Transactional
    public ResponseEntity deleteProduct(@PathVariable String id){
        Optional<Product> optionalProduct = productRepository.findById(id);

        if(optionalProduct.isPresent()){
            Product productDelete = optionalProduct.get();
            productRepository.delete(productDelete);
            return ResponseEntity.noContent().build();

        }else{
            throw  new EntityNotFoundException();
        }
    }

    // localhost:8080/product/remove/{id}
    @DeleteMapping("remove/{id}")
    @Transactional
    public ResponseEntity removeProduct(@PathVariable String id){
        Optional<Product> optionalProduct = productRepository.findById(id);

        if(optionalProduct.isPresent()){
            Product productDelete = optionalProduct.get();
            productDelete.setActive(false);
            return ResponseEntity.noContent().build();

        }else{
            throw new EntityNotFoundException();
        }
    }
}
