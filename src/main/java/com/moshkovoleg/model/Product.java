package com.moshkovoleg.model;

import com.sun.istack.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import jakarta.persistence.*;

@Entity
@Table(name = "products")
@NoArgsConstructor
@AllArgsConstructor
public class Product {
    @Id
    @Getter
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "product_id")
    private Long productId;

    @Getter
    @Setter
    @NotNull
    @Column(name = "product_name")
    private String productName;

    @Getter
    @Setter
    @NotNull
    @Column(name = "product_price")
    private Double productPrice;

}
