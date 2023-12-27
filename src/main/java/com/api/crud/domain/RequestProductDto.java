package com.api.crud.domain;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record RequestProductDto(
        String id,
        @NotBlank String name,
        @NotNull Integer price_in_cents) { }
