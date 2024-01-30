package com.api.crud.infra.security;

import com.api.crud.domain.user.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    /* Classe para gerar os tokens */
    @Value("${api.security.token.secret}")
    private String secret;

    public String generateToken(User user) { // Método para gerar um token JWT com base nas informações do usuário
        try {
            // Criação de um algoritmo de assinatura usando a chave secreta
            Algorithm algorithm = Algorithm.HMAC256(secret);

            // Criação do token JWT com informações específicas (emissor, assunto, data de expiração) e assinado
            String token = JWT.create()
                    .withIssuer("auth-api")
                    .withSubject(user.getLogin())
                    .withExpiresAt(genExpirationDate())
                    .sign(algorithm);

            return token;
        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating token", exception);
        }
    }

    public String validateToken(String token){ // Método para validar um token JWT
        try {
            // Criação de um algoritmo de verificação usando a chave secreta
            Algorithm algorithm = Algorithm.HMAC256(secret);

            // Validação do token JWT, obtendo o assunto (normalmente, o login do usuário)
            return JWT.require(algorithm)
                    .withIssuer("auth-api")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException exception){
            return "";
        }
    }

    private Instant genExpirationDate() { // Método privado para gerar a data de expiração do token (2 horas a partir do momento atual)
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
