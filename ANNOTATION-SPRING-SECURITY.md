# Interface UserDetails

O termo "UserDetails" está associado ao contextos que envolvem autenticação e autorização. No entanto, é importante notar que UserDetails em si pode variar dependendo do framework ou biblioteca que está sendo utilizado. Vou abordar o conceito geral e alguns métodos comuns associados a UserDetails no contexto do Spring Security, que é uma estrutura popular para segurança em aplicativos Java.

No Spring Security, UserDetails é uma interface fundamental que representa informações sobre um usuário, como nome de usuário, senha, papéis (roles) e outras informações relacionadas à segurança. Ela é frequentemente utilizada para encapsular dados do usuário durante o processo de autenticação.

Alguns métodos comuns associados à interface UserDetails no Spring Security:

1. **getUsername():** Retorna o nome de usuário associado ao UserDetails.

   ```java
   String getUsername();
   ```

2. **getPassword():** Retorna a senha associada ao UserDetails. Geralmente, as senhas são mantidas como strings criptografadas.

   ```java
   String getPassword();
   ```

3. **getAuthorities():** Retorna uma coleção de objetos GrantedAuthority que representam os papéis (roles) do usuário.

   ```java
   Collection<? extends GrantedAuthority> getAuthorities();
   ```

4. **isEnabled():** Indica se o usuário está habilitado ou desabilitado. Usado para contas que podem ser desativadas por motivos de segurança.

   ```java
   boolean isEnabled();
   ```

5. **isAccountNonExpired(), isAccountNonLocked(), isCredentialsNonExpired():** Métodos que indicam se a conta do usuário não está expirada, não está bloqueada e as credenciais não estão expiradas, respectivamente.

   ```java
   boolean isAccountNonExpired();
   boolean isAccountNonLocked();
   boolean isCredentialsNonExpired();
   ```

6. **getDetails():** Retorna informações adicionais sobre o usuário. Este método geralmente é usado para fornecer detalhes específicos da aplicação associados ao usuário.

   ```java
   Object getDetails();
   ```

Implementar a interface UserDetails é comum ao criar uma classe customizada que representa os detalhes do usuário em um aplicativo Spring Security. Além disso, é necessário fornecer uma implementação personalizada de UserDetails no serviço de UserDetails, geralmente implementando a interface UserDetailsService, para carregar os detalhes do usuário durante o processo de autenticação.

Esses são apenas alguns dos métodos associados à interface UserDetails no contexto do Spring Security. 

# Enum UserRole

O enum `UserRole` representa os diferentes papéis (ou funções) que os usuários podem ter em um sistema. Em muitos sistemas de controle de acesso e autenticação, é comum atribuir diferentes papéis aos usuários para controlar suas permissões e acessos. Nesse caso, a enumeração define dois papéis: ADMIN e USER.

```java
package com.api.crud.domain.user;

public enum UserRole {
    ADMIN("admin"),
    USER("user");

    private String role;

    UserRole(String role) {
        this.role = role;
    }

    public String getRole(){
        return role;
    }
}
```

A enumeração tem os seguintes elementos:

1. **ADMIN:** Representa o papel de administrador no sistema.
2. **USER:** Representa o papel de usuário padrão no sistema.

Cada elemento da enumeração é instanciado com um argumento de string associado ao papel. Isso é feito através do construtor `UserRole(String role)`, onde o argumento `role` é uma string que descreve o papel.

```java
private String role;

UserRole(String role) {
    this.role = role;
}
```

Além disso, a enumeração fornece um método público chamado `getRole()`, que retorna a string associada ao papel. Esse método pode ser útil ao trabalhar com esses papéis em código, permitindo que você obtenha a representação textual do papel.

```java
public String getRole(){
    return role;
}
```

Isso pode ser usado, por exemplo, ao atribuir papéis a usuários no código ou ao verificar os papéis de um usuário durante o processo de autenticação e autorização.

Em resumo, a enumeração `UserRole` fornece uma maneira estruturada de representar os diferentes papéis de usuário em um sistema, facilitando o gerenciamento e a manipulação desses papéis em código. Ela encapsula a lógica associada a esses papéis em uma estrutura mais organizada e orientada a objetos.

# Classe User

A classe `User` é uma entidade persistente em um banco de dados relacionado a usuários em um sistema. Esta classe está integrada com o Spring Security, pois implementa a interface `UserDetails`. 

```java
@Table(name = "users")
@Entity(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class User implements UserDetails {

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
```

Analisando cada parte do código:

1. **Anotações JPA (`@Table` e `@Entity`):**
   ```java
   @Table(name = "users")
   @Entity(name = "users")
   ```

   Essas anotações são usadas em aplicações Java que utilizam o Java Persistence API (JPA) para mapear objetos Java para tabelas de banco de dados. A anotação `@Table` especifica o nome da tabela no banco de dados (neste caso, "users"), e `@Entity` especifica o nome da entidade (também "users"). Isso implica que esta classe está associada à tabela "users" no banco de dados.

2. **Lombok (`@Getter`, `@Setter`, `@NoArgsConstructor`, `@AllArgsConstructor`, `@EqualsAndHashCode`):**
   ```java
   @Getter
   @Setter
   @NoArgsConstructor
   @AllArgsConstructor
   @EqualsAndHashCode(of = "id")
   ```

   Essas são anotações do projeto Lombok, que é uma biblioteca que visa reduzir a verbosidade do código Java. Elas geram automaticamente métodos como getters, setters, construtores sem argumentos, construtores com todos os argumentos e métodos `equals` e `hashCode` baseados nos campos da classe. A anotação `@EqualsAndHashCode(of = "id")` indica que a comparação de igualdade e geração de hash deve ser baseada apenas no campo `id`.

3. **Atributos da Classe:**
   ```java
   private String id;
   private String login;
   private String password;
   private UserRole role;
   ```

   Estes são os atributos da classe, representando informações sobre o usuário. `id` parece ser um identificador único, `login` e `password` representam as credenciais de login, e `role` é do tipo `UserRole`, uma enumeração que define os papéis do usuário.

4. **Método Construtor Adicional:**
   ```java
   public User(String login, String password, UserRole role){
       this.login = login;
       this.password = password;
       this.role = role;
   }
   ```

   Este é um construtor adicional que permite criar uma instância da classe `User` fornecendo diretamente o login, a senha e o papel do usuário.

5. **Métodos da Interface `UserDetails`:**
   ```java
   @Override
   public Collection<? extends GrantedAuthority> getAuthorities() {
       // Implementação para retornar papéis do usuário como GrantedAuthority
   }

   @Override
   public String getUsername() {
       // Implementação para retornar o nome de usuário
   }

   @Override
   public boolean isAccountNonExpired() {
       // Implementação para verificar se a conta não está expirada
   }

   @Override
   public boolean isAccountNonLocked() {
       // Implementação para verificar se a conta não está bloqueada
   }

   @Override
   public boolean isCredentialsNonExpired() {
       // Implementação para verificar se as credenciais não estão expiradas
   }

   @Override
   public boolean isEnabled() {
       // Implementação para verificar se o usuário está habilitado
   }
   ```

   Esses métodos fazem parte da implementação da interface `UserDetails`, que é usada pelo Spring Security para obter informações sobre o usuário durante o processo de autenticação e autorização. Cada método retorna informações específicas sobre o usuário, como papéis, nome de usuário e status de conta.

Em resumo, a classe `User` é uma entidade persistente que representa usuários em um sistema, integrada com o Spring Security para fornecer informações necessárias durante a autenticação e autorização. O uso de anotações do Lombok reduz a boilerplate do código, e a implementação da interface `UserDetails` permite a integração com o Spring Security.

# Interface UserRepository

A interface `UserRepository` que estende `JpaRepository` e é anotada com `@Repository` que sugere que a interface é parte de uma aplicação Spring que utiliza o Spring Data JPA para interagir com um banco de dados, e que ela é responsável por operações relacionadas à entidade `User`.

```java
package com.api.crud.repository;

import com.api.crud.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    UserDetails findByLogin(String login);
}
```

Principais elementos do script:

1. **`@Repository`:**
   ```java
   @Repository
   ```

   A anotação `@Repository` é uma anotação do Spring que indica que a interface é um componente responsável pelo acesso a dados (um repositório de dados). Isso permite que o Spring trate esta interface como um bean gerenciado, e também habilita a tradução de exceções específicas do banco de dados para exceções mais genéricas do Spring.

2. **`UserRepository` extends `JpaRepository<User, String>`:**
   ```java
   public interface UserRepository extends JpaRepository<User, String> {
   ```

   `UserRepository` estende a interface `JpaRepository`, que é parte do Spring Data JPA. `JpaRepository` fornece métodos convenientes para realizar operações CRUD (Create, Read, Update, Delete) no banco de dados relacionado à entidade `User`. A interface `JpaRepository` tem dois parâmetros genéricos: o tipo da entidade (`User`) e o tipo do identificador (`String`).

3. **Método `findByLogin(String login)`:**
   ```java
   UserDetails findByLogin(String login);
   ```

   Este método declara uma consulta personalizada para encontrar um usuário pelo nome de usuário (`login`). O retorno do método é do tipo `UserDetails`, que é uma interface do Spring Security para representar os detalhes do usuário durante a autenticação e autorização.

   É importante notar que, normalmente, o método deveria retornar uma instância de `UserDetails` específica para o seu domínio, não apenas um `UserDetails`. Se a intenção é retornar um usuário específico do banco de dados e convertê-lo em `UserDetails`, o método pode precisar de uma implementação mais elaborada.

   Se este método for utilizado para autenticação, pode ser necessário verificar se o usuário existe no banco de dados, buscar suas informações e criar um objeto `UserDetails` apropriado.

Em resumo, `UserRepository` é uma interface Spring Data JPA que fornece métodos convenientes para operações relacionadas a usuários no banco de dados. A anotação `@Repository` indica que esta interface é um componente de acesso a dados gerenciado pelo Spring. O método `findByLogin` é uma consulta personalizada para recuperar detalhes do usuário pelo nome de usuário.

# Interface UserDetailsService

A interface `UserDetailsService` é parte do Spring Security e é fundamental para a autenticação de usuários. Ela define um único método chamado `loadUserByUsername`, que deve ser implementado para carregar informações sobre o usuário com base no nome de usuário. O propósito principal do `UserDetailsService` é fornecer ao sistema de autenticação do Spring Security os detalhes necessários do usuário durante o processo de login.

A assinatura da interface `UserDetailsService` é a seguinte:

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

Discutindo os detalhes do método `loadUserByUsername`:

- **Parâmetro `username`:** Este é o nome de usuário fornecido durante o processo de autenticação. O objetivo do método é localizar as informações do usuário associadas a esse nome de usuário.

- **Retorno `UserDetails`:** O método retorna uma implementação da interface `UserDetails`. `UserDetails` é uma interface do Spring Security que representa os detalhes do usuário durante a autenticação e autorização. Implementações típicas incluem a classe `User` do Spring Security ou classes personalizadas que implementam `UserDetails`.

- **Exceção `UsernameNotFoundException`:** Esta exceção deve ser lançada se o usuário não for encontrado com base no nome de usuário fornecido. Isso é importante para indicar que o nome de usuário não existe e, portanto, o processo de autenticação não pode ser concluído com sucesso.

A implementação do método `loadUserByUsername` pode variar dependendo da fonte de dados utilizada para armazenar informações do usuário. Em muitos casos, essa implementação envolverá a consulta a um banco de dados para recuperar as informações do usuário.

Vale resssaltar que é preciso anotar a classe que implementa `UserDetailsService` com `@Service` para que o Spring a reconheça como um componente gerenciado. Isso permite a injeção dessa implementação onde for necessário, como no caso de configuração do Spring Security.

# Classe AuthorizationService

Essa é a classe `AuthorizationService` que implementa a interface `UserDetailsService`. 

```java
package com.api.crud.services;

import com.api.crud.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthorizationService implements UserDetailsService {

    @Autowired
    UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // Carrega as informações sobre o usuário com base no nome de usuário.
        return repository.findByLogin(username);
    }
}
```

Analisando cada parte do código:

1. **Anotação `@Service`:**
   ```java
   @Service
   ```

   A anotação `@Service` é usada para indicar que a classe é um componente de serviço no contexto do Spring. Isso significa que o Spring irá reconhecê-la como um componente gerenciado, permitindo a injeção de dependências, entre outras funcionalidades.

2. **Implementação da Interface `UserDetailsService`:**
   ```java
   public class AuthorizationService implements UserDetailsService {
   ```

   A classe `AuthorizationService` implementa a interface `UserDetailsService`. Isso significa que ela fornece uma implementação para o método `loadUserByUsername`, que é utilizado pelo Spring Security para carregar as informações do usuário durante o processo de autenticação.

3. **Atributo `repository`:**
   ```java
   @Autowired
   UserRepository repository;
   ```

   O atributo `repository` é anotado com `@Autowired`, indicando que o Spring deve injetar automaticamente uma instância de `UserRepository` nesse atributo. Isso indica que a classe `AuthorizationService` dependerá do `UserRepository` para obter as informações do usuário durante a autenticação.

4. **Método `loadUserByUsername`:**
   ```java
   @Override
   public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       return repository.findByLogin(username);
   }
   ```

   Este método é uma implementação do método definido na interface `UserDetailsService`. Ele recebe um nome de usuário como parâmetro e utiliza o método `findByLogin` do `UserRepository` para recuperar as informações do usuário associadas a esse nome de usuário. Em seguida, retorna o resultado diretamente.

É importante notar que a implementação desse método deve retornar uma instância de `UserDetails`. No entanto, a implementação fornecida retorna diretamente o resultado do método `findByLogin`, que é uma instância de `User`. Isso pode funcionar se a classe `User` implementar a interface `UserDetails`, ou se houver uma conversão adequada.

# Interface SecurityFilterChain

A interface `SecurityFilterChain` é parte do framework Spring Security e é usada para representar a configuração de filtros de segurança em um aplicativo web. Ela é uma parte fundamental da configuração de segurança em aplicativos baseados no Spring Security.

A assinatura básica da interface é a seguinte:

```java
public interface SecurityFilterChain extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    // Métodos e configurações específicas aqui
}
```

Essa interface é implementada para criar e configurar a cadeia de filtros de segurança que serão aplicados às requisições HTTP no aplicativo. A cadeia de filtros é uma série de filtros que processam as requisições e respostas HTTP, adicionando funcionalidades de segurança, autenticação e autorização.

O método mais comum usado para configurar `SecurityFilterChain` é `public SecurityFilterChain filterChain(HttpSecurity http) throws Exception`, que recebe uma instância de `HttpSecurity` e retorna uma instância de `SecurityFilterChain`. Esse método é frequentemente utilizado ao configurar a segurança em uma classe de configuração marcada com `@EnableWebSecurity`.

A configuração da `SecurityFilterChain` geralmente envolve a definição de regras de autorização, autenticação, configuração de sessão, entre outras considerações de segurança. 

# Classe SecurityConfiguration

Essa classe representa uma configuração de segurança para um aplicativo web usando o Spring Security. 

```java
package com.api.crud.infra.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize.requestMatchers(HttpMethod.POST, "/product").hasRole("ADMIN").anyRequest().authenticated())
                .build();
    }
}
```

Analisando as principais anotações e métodos do script:

1. **`@Configuration`:**
   ```java
   @Configuration
   ```

   A anotação `@Configuration` indica que a classe é uma classe de configuração para o Spring. No contexto de segurança, ela é usada para configurar as políticas de segurança.

2. **`@EnableWebSecurity`:**
   ```java
   @EnableWebSecurity
   ```

   A anotação `@EnableWebSecurity` habilita a segurança web no aplicativo. Esta anotação é uma maneira conveniente de importar a configuração padrão do Spring Security para aplicativos baseados na web.

3. **Método `securityFilterChain`:**
   ```java
   @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
       // Configuração da política de segurança
   }
   ```

   Este método cria e retorna uma instância de `SecurityFilterChain`, que representa a configuração da política de segurança para o aplicativo.

4. **Configuração do `httpSecurity`:**
   ```java
   return httpSecurity.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize.requestMatchers(HttpMethod.POST, "/product").hasRole("ADMIN").anyRequest().authenticated())
                .build();
   ```

   - **`.csrf(csrf -> csrf.disable())`:** Desabilita a proteção contra CSRF (Cross-Site Request Forgery). Em alguns casos, desabilitar CSRF pode ser aceitável, mas é importante considerar as implicações de segurança ao fazer isso.

   - **`.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))`:** Configura a política de gerenciamento de sessão como STATELESS. Isso significa que o aplicativo não criará ou usará sessões de usuário. Essa configuração é típica para aplicativos que usam autenticação baseada em tokens, como JWT (JSON Web Tokens).

   - **`.authorizeHttpRequests(...)`:** Configura a autorização para as requisições HTTP. No meu exemplo fornecido, há uma autorização específica para requisições HTTP POST para "/product". A configuração indica que apenas usuários com a função (role) "ADMIN" têm permissão para acessar essa URL. Para qualquer outra requisição (`.anyRequest()`), o usuário deve estar autenticado.

   Neste exemplo, o método `securityFilterChain` está configurando a política de segurança para desabilitar CSRF, definir a política de gerenciamento de sessão como STATELESS e autorizar requisições específicas. O retorno é uma instância de `SecurityFilterChain` que encapsula essa configuração.

   Vale ressaltar que a configuração exata da `SecurityFilterChain` pode variar de acordo com os requisitos específicos do seu aplicativo. Ela oferece flexibilidade para definir uma ampla gama de políticas de segurança e filtros, adaptando-se às necessidades da sua aplicação.
   
   É importante notar que este é apenas um exemplo e a configuração de segurança pode variar com base nos requisitos específicos do aplicativo. A implementação real pode envolver outras configurações, como autenticação de usuários, definição de roles, personalização de páginas de login, entre outros. 

--- 

# Autor
## Feito por: `Daniel Penelva de Andrade`