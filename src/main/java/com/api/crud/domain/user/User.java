package com.api.crud.domain.user;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Table(name = "users")
@Entity(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    private String login;
    private String password;
    private UserRole role;

    public User(String login, String password, UserRole role){
        this.login = login;
        this.password = password;
        this.role = role;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { // Retorna uma coleção de objetos GrantedAuthority que representam os papéis (roles) do usuário.
        if(this.role == UserRole.ADMIN) return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER"));
        else return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getUsername() { // Retorna o nome de usuário associado ao UserDetails.
        return login;
    }

    @Override
    public boolean isAccountNonExpired() { // Indica se a conta do usuário não está expirada
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { // Indica se a conta não está bloqueada
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // Indica se as credenciais não estão expiradas
        return true;
    }

    @Override
    public boolean isEnabled() { // Indica se o usuário está habilitado ou desabilitado.
        return true;
    }
}
