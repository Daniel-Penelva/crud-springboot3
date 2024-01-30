package com.api.crud.infra.security;

import com.api.crud.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    TokenService tokenService;

    @Autowired
    UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        var token = this.recoverToken(request); // Recupera o token da requisição

        // Se o token não for nulo, realiza a validação
        if(token != null){
            var login = tokenService.validateToken(token); // Valida o token usando o serviço TokenService e recupera o login do usuário
            UserDetails user = userRepository.findByLogin(login); // Recupera informações do usuário do banco de dados usando o UserRepository

            // Cria uma instância de UsernamePasswordAuthenticationToken com base nas informações do usuário e a define no contexto de segurança usando SecurityContextHolder
            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response); // Continua o processamento da requisição
    }

    private String recoverToken(HttpServletRequest request){ // Método privado para recuperar o token do cabeçalho da requisição

        var authHeader = request.getHeader("Authorization"); // Obtém o valor do cabeçalho "Authorization"
        if(authHeader == null) return null; // Se o cabeçalho não estiver presente, retorna nulo
        return authHeader.replace("Bearer ", ""); // Remove a parte "Bearer " do valor do cabeçalho, deixando apenas o token JWT
    }
}
