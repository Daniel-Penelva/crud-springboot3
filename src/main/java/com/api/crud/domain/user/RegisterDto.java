package com.api.crud.domain.user;

public record RegisterDto(String login, String password, UserRole role) {
}
