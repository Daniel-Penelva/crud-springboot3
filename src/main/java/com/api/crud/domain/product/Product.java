package com.api.crud.domain.product;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "product")
@Getter
@Setter
@EqualsAndHashCode(of = "id")
@AllArgsConstructor
@NoArgsConstructor
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String name;

    private Integer price_in_cents;

    private Boolean active;

    public Product(RequestProductDto requestProductDto) {
        this.name = requestProductDto.name();
        this.price_in_cents = requestProductDto.price_in_cents();
        this.active = true;
    }
}
