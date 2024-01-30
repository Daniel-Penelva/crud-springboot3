package com.api.crud.controllers;

import com.api.crud.domain.user.AuthenticationDto;
import com.api.crud.domain.user.LoginResponseDto;
import com.api.crud.domain.user.RegisterDto;
import com.api.crud.domain.user.User;
import com.api.crud.infra.security.TokenService;
import com.api.crud.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
public class AuthenticationController {

    /* Classe que valida se os usuários estão autenticados para que consigam acessar os endpoints (métodos HTTP) que estão privados. Nessa classe terá
    * um endpoint de validação para validar os usuários, ou seja, um endpoint onde o usuário fará o login, passando o login e a senha para validar seu acesso,
    * nele será passado um token. */

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenService tokenService;

    // http://localhost:8080/auth/login
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Valid AuthenticationDto data){

        // Vale ressaltar que não é uma boa prática salvar o valor do password no BD, o correto é salvar o hash dessa senha (criptografia da senha).
        // Lembrando que as consultas também serão em hash.

        var userNamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password()); // Criando um objeto UsernamePasswordAuthenticationToken com as credenciais fornecidas (login e senha)
        var auth = this.authenticationManager.authenticate(userNamePassword); // Autenticando o usuário utilizando o AuthenticationManager

        var token = tokenService.generateToken((User) auth.getPrincipal());// Adição da linha para gerar um token usando o TokenService

        return ResponseEntity.ok(new LoginResponseDto(token));
    }

    // http://localhost:8080/auth/register
    @PostMapping("/register")
    public ResponseEntity register(@RequestBody @Valid RegisterDto data){ // Esse endpoint no SecurityConfiguration vai ser configurado para que somente o role ADMIN possa criar usuário
        if(this.userRepository.findByLogin(data.login()) != null) return ResponseEntity.badRequest().build(); // Verificando se já existe um usuário com o mesmo login no banco de dados

        String encryptedPassword = new BCryptPasswordEncoder().encode(data.password()); // Criptografando a senha usando BCryptPasswordEncoder

        User newUser = new User(data.login(), encryptedPassword, data.role()); // Criando um novo usuário com as informações fornecidas (login, senha criptografada e role)

        this.userRepository.save(newUser); // Salvando o novo usuário no banco de dados utilizando o UserRepository

        return ResponseEntity.ok().build(); // Retornando uma resposta HTTP 200 OK se o registro for bem-sucedido
    }

}
