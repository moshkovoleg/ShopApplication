package com.moshkovoleg.controller;

import com.moshkovoleg.model.Product;
import com.moshkovoleg.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/v1")
public class ProductController {
    private final ProductService productService;
    private AuthenticationManager authManager;

    //ALL USERS CAN USE
    @Autowired
    public ProductController(ProductService productService) {
        this.productService = productService;
    }


    @CrossOrigin
    @GetMapping("/products")
    public List<Product> getAll(){
        return productService.getAll();
    }

    @CrossOrigin
    @GetMapping("/products/{id}")
    public ResponseEntity<Product> getById(@PathVariable("id") Long id){
        if(productService.getById(id).isPresent()){
            return ResponseEntity.of(productService.getById(id));
        }
        else{
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Product Not Found");
        }

    }

    //ONLY AUTHORIZED USERS CAN USE

    private Set<Optional<Product>> cart = new HashSet<Optional<Product>>();

    @CrossOrigin
    @GetMapping("/cart")
    @PreAuthorize("hasAuthority('cart:write')")
    public Set<Optional<Product>> getMain(){
        return cart;
    }

    @CrossOrigin
    @PostMapping("/cart")
    @PreAuthorize("hasAuthority('cart:write')")
    public Boolean addToCart(@RequestBody Product product){
        return cart.add(productService.getById(product.getProductId()));
    }

    @CrossOrigin
    @DeleteMapping("/cart/{id}")
    @PreAuthorize("hasAuthority('cart:write')")
    public Boolean delFromCart(@PathVariable("id") Long id){
        return cart.remove(productService.getById(id));
    }

    //ONLY ADMINS CAN USE
    @CrossOrigin
    @PostMapping("/admin/product")
    @PreAuthorize("hasAuthority('products:write')")
    public Product addProduct(@RequestBody Product product){
        return productService.addProduct(product);
    }

    @CrossOrigin
    @DeleteMapping("/admin/product/{id}")
    @PreAuthorize("hasAuthority('products:write')")
    public void delProductById(@PathVariable("id") Long id){
       productService.delById(id);
    }

}
