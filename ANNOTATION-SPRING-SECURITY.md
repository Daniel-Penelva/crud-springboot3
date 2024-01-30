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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

   @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
      return httpSecurity.csrf(csrf -> csrf.disable())
              .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
              .authorizeHttpRequests(authorize -> authorize
                      .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                      .requestMatchers(HttpMethod.POST, "/auth/register").permitAll() // configuração apenas para teste, aqui permite que todos os usuarios possam registrar um novo usuario. Mas o correto seria acessar o BD e modificar um registro do usuario atribuindo o role como ADMIN.
                      .requestMatchers(HttpMethod.POST, "/product").hasRole("ADMIN").anyRequest().authenticated())
              .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
              .build();
   }

   @Bean
   public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
      return authenticationConfiguration.getAuthenticationManager();
   }

   @Bean
   public PasswordEncoder passwordEncoder(){ // Faz a criptografia de hash na senha
      return new BCryptPasswordEncoder();
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
              .authorizeHttpRequests(authorize -> authorize
                      .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                      .requestMatchers(HttpMethod.POST, "/auth/register").permitAll() 
                      .requestMatchers(HttpMethod.POST, "/product").hasRole("ADMIN").anyRequest().authenticated())
              .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
              .build();
   ```

   - **`.csrf(csrf -> csrf.disable())`:** Desabilita a proteção contra CSRF (Cross-Site Request Forgery). Em alguns casos, desabilitar CSRF pode ser aceitável, mas é importante considerar as implicações de segurança ao fazer isso.

   - **`.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))`:** Configura a política de gerenciamento de sessão como STATELESS. Isso significa que o aplicativo não criará ou usará sessões de usuário. Essa configuração é típica para aplicativos que usam autenticação baseada em tokens, como JWT (JSON Web Tokens).

   - **`.authorizeHttpRequests(...)`:** Configura a autorização para as requisições HTTP. No meu exemplo fornecido, há uma autorização específica para requisições HTTP POST para "/product". A configuração indica que apenas usuários com a função (role) "ADMIN" têm permissão para acessar essa URL. Para qualquer outra requisição (`.anyRequest()`), o usuário deve estar autenticado.

   ```java
   .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
   .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
   ```

   - Essas duas linhas configuram exceções específicas para permitir que determinados endpoints (caminhos) aceitem requisições POST sem autenticação. Analisando cada uma delas:

    **`/auth/login`:**
   ```java
   .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
   ```
   - Esta linha configura que qualquer requisição POST para o endpoint `/auth/login` seja permitida sem a necessidade de autenticação. Em outras palavras, ela permite que qualquer usuário, autenticado ou não, acesse o endpoint de login sem restrições.

   **`/auth/register`:**
   ```java
   .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
   ```
   - Similar à linha anterior, esta configuração permite que qualquer requisição POST para o endpoint `/auth/register` seja aceita sem autenticação. Isso é útil para permitir que novos usuários se registrem no sistema sem a necessidade de fornecer credenciais de autenticação.

   - Ambas as configurações são usadas para permitir operações de autenticação e registro sem restrições de autenticação, possivelmente para facilitar o teste dessas funcionalidades. No entanto, como mencionado no comentário, essa é uma configuração temporária e, em ambientes de produção, seria mais apropriado implementar uma lógica segura para lidar com a criação de novos usuários e a autenticação.

   - É importante notar que permitir operações sem autenticação, especialmente o registro de novos usuários, pode ter implicações de segurança. Em um ambiente de produção, geralmente deseja implementar uma lógica mais robusta, como a validação de credenciais e a atribuição apropriada de papéis (roles), como mencionado no comentário, para garantir a integridade e a segurança do sistema.

   **`/product`:**

   ```java
    .requestMatchers(HttpMethod.POST, "/product").hasRole("ADMIN").anyRequest().authenticated()
   ```
   - Esta linha faz parte da configuração de autorização do Spring Security e define as permissões de acesso para o endpoint `/product` quando a requisição é um método `POST`. Analisando cada parte:

   **`.requestMatchers(HttpMethod.POST, "/product")`**:
   - Especifica que as configurações de autorização seguintes se aplicam somente às requisições HTTP com o método `POST` para o endpoint `/product`.

   **`.hasRole("ADMIN")`**:
   - Exige que o usuário autenticado tenha a role (papel) "ADMIN". As roles são uma forma comum de atribuir permissões aos usuários em sistemas baseados em Spring Security.

   **`.anyRequest().authenticated()`**:
   - Para qualquer outra requisição que não se enquadre nas condições anteriores, exige que o usuário esteja autenticado. Isso significa que, para qualquer outro endpoint além de `/product` com método `POST`, o usuário precisa estar autenticado.

   - Em resumo, esta linha está configurando as permissões para o endpoint `/product` quando a requisição é um método `POST`. Para acessar esse endpoint, o usuário precisa estar autenticado e ter a role "ADMIN". Para outros endpoints e métodos, é exigida apenas a autenticação, sem uma exigência específica de role. Isso é uma prática comum em sistemas onde certos endpoints, como operações de administração, exigem permissões mais elevadas.


   **`addFilterBefore()`:**
   ```java
   .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
   ```
   - Essa linha adicionada `.addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)` está incluindo o meu filtro personalizado `securityFilter` antes do `UsernamePasswordAuthenticationFilter` na cadeia de filtros do Spring Security. Entendendo o que isso significa:

   - **`.addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)`**:

   - Este método é utilizado para adicionar um filtro personalizado (`securityFilter`) antes de um filtro específico na cadeia de filtros do Spring Security.

   - `securityFilter` é uma instância do meu filtro personalizado, que estende `OncePerRequestFilter`.

   - `UsernamePasswordAuthenticationFilter.class` é a classe do filtro padrão do Spring Security responsável pelo processamento da autenticação baseada em nome de usuário e senha.

   **Razão para Adicionar o Filtro Personalizado Antes do Filtro Padrão**:

   - Ao adicionar meu filtro personalizado antes do `UsernamePasswordAuthenticationFilter`, estou indicando que desejo que meu filtro seja executado antes do filtro padrão de autenticação por nome de usuário e senha.

   - Isso é útil quando precisa personalizar ou estender a lógica de autenticação padrão do Spring Security. O meu filtro pode executar operações adicionais antes do filtro padrão ser acionado.

   - Em muitos casos, isso é usado para a validação de tokens JWT, onde o filtro personalizado verifica se um token está presente na solicitação antes de permitir que o filtro padrão de autenticação por nome de usuário e senha prossiga.

   - Ao Adicionar meu filtro antes do filtro padrão permite que tenha controle sobre a lógica de autenticação personalizada antes que o Spring Security tente autenticar com base em credenciais de nome de usuário e senha.

   **Importância da Ordem dos Filtros**:

   - A ordem dos filtros é significativa. A execução dos filtros ocorre na ordem em que são adicionados à cadeia.

   - Ao adicionar um filtro antes de outro, você influencia a ordem de execução. Isso é particularmente importante ao lidar com autenticação personalizada, pois você deseja que a lógica do seu filtro seja aplicada antes da lógica de autenticação padrão.

   - Em resumo, a linha adicionada está configurando a cadeia de filtros do Spring Security para executar primeiro o seu filtro personalizado `securityFilter` antes do filtro padrão `UsernamePasswordAuthenticationFilter`, permitindo a execução da lógica personalizada antes da tentativa de autenticação padrão.

Neste exemplo, o método `securityFilterChain` está configurando a política de segurança para desabilitar CSRF, definir a política de gerenciamento de sessão como STATELESS e autorizar requisições específicas. O retorno é uma instância de `SecurityFilterChain` que encapsula essa configuração.

Vale ressaltar que a configuração exata da `SecurityFilterChain` pode variar de acordo com os requisitos específicos do seu aplicativo. Ela oferece flexibilidade para definir uma ampla gama de políticas de segurança e filtros, adaptando-se às necessidades da sua aplicação.
   
É importante notar que este é apenas um exemplo e a configuração de segurança pode variar com base nos requisitos específicos do aplicativo. A implementação real pode envolver outras configurações, como autenticação de usuários, definição de roles, personalização de páginas de login, entre outros.



5. **Método `authenticationManager`:**
   ```java
   @Bean
   public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
       return authenticationConfiguration.getAuthenticationManager();
   }
   ```

   Este método cria e retorna um bean do tipo `AuthenticationManager`. O `AuthenticationManager` é uma interface central no Spring Security que gerencia a autenticação de usuários. O método recebe uma instância de `AuthenticationConfiguration` como parâmetro, que é uma configuração de autenticação fornecida pelo Spring Security.

   A criação do bean `AuthenticationManager` é importante para que ele possa ser injetado em outros componentes ou configurações que precisem dele. Ele é frequentemente usado em configurações de autenticação personalizada.

6. **Método `passwordEncoder`:**
   ```java
   @Bean
   public PasswordEncoder passwordEncoder(){ // Faz a criptografia de hash na senha
       return new BCryptPasswordEncoder();
   }
   ```

   Este método cria e retorna um bean do tipo `PasswordEncoder`. O `PasswordEncoder` é uma interface no Spring Security usada para realizar a criptografia de senha. No exemplo fornecido, está sendo utilizado o `BCryptPasswordEncoder`, que é uma implementação popular que utiliza o algoritmo de hash BCrypt.

   A criptografia de senha é crucial para a segurança de um aplicativo, pois armazena as senhas de forma segura no banco de dados, evitando que senhas em texto plano sejam comprometidas em caso de violação de dados. O `PasswordEncoder` é usado durante o processo de autenticação para comparar a senha fornecida pelo usuário com a senha armazenada no banco de dados.

   Configurar um `PasswordEncoder` como um bean permite que o Spring Security o injete automaticamente onde for necessário no processo de autenticação, garantindo que a senha seja manipulada de maneira segura.

Em resumo, esses métodos adicionados à classe `SecurityConfiguration` são responsáveis por criar beans importantes relacionados à autenticação em um aplicativo Spring Security. O `AuthenticationManager` gerencia o processo de autenticação, enquanto o `PasswordEncoder` realiza a criptografia de senha, promovendo boas práticas de segurança. Ambos são componentes essenciais para garantir um sistema de autenticação robusto e seguro.

# Classe UsernamePasswordAuthenticationToken e BCryptPasswordEncoder

Sobre as classes `UsernamePasswordAuthenticationToken` e `BCryptPasswordEncoder`:

1. **`UsernamePasswordAuthenticationToken`:**
   - A classe `UsernamePasswordAuthenticationToken` é parte do framework Spring Security e é uma implementação da interface `Authentication`. Ela representa um token de autenticação que contém as credenciais do usuário, como nome de usuário e senha.
   - Geralmente, é usado para encapsular as credenciais durante o processo de autenticação. Por exemplo, quando um usuário envia suas credenciais (nome de usuário e senha) durante o login, essas informações podem ser encapsuladas em um objeto `UsernamePasswordAuthenticationToken` antes de serem processadas pelo `AuthenticationManager`.
   - Durante a autenticação, o `AuthenticationManager` verifica as credenciais fornecidas e, se a autenticação for bem-sucedida, cria um objeto `Authentication` que inclui um `UsernamePasswordAuthenticationToken` entre outras informações.

2. **`BCryptPasswordEncoder`:**
   - A classe `BCryptPasswordEncoder` é uma implementação da interface `PasswordEncoder` do Spring Security, usada para realizar a criptografia de senhas usando o algoritmo de hash BCrypt.
   - O BCrypt é um algoritmo de hash projetado para ser computacionalmente intensivo e lento, o que o torna resistente a ataques de força bruta. Ele adiciona automaticamente um "salt" aleatório para cada senha, melhorando a segurança.
   - No contexto de segurança, ao armazenar senhas no banco de dados, é uma prática recomendada armazenar apenas o hash da senha em vez da senha real. Isso evita que as senhas sejam expostas em caso de violação de dados.
   - Ao usar o `BCryptPasswordEncoder`, você pode gerar o hash de uma senha antes de armazená-la no banco de dados e comparar esse hash com as senhas fornecidas durante o processo de autenticação.

Exemplo simples de uso do `BCryptPasswordEncoder` para gerar o hash de uma senha:

```java
String senha = "senha123";
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hashSenha = encoder.encode(senha);

// Agora, você pode armazenar hashSenha no banco de dados
```

Ao comparar senhas durante a autenticação, você usa o método `matches` do `BCryptPasswordEncoder`:

```java
String senhaDigitada = "senhaDigitadaPeloUsuario";
if (encoder.matches(senhaDigitada, hashSenhaDoBancoDeDados)) {
    // A senha fornecida está correta
} else {
    // A senha fornecida está incorreta
}
```

Essas classes são componentes-chave em cenários de autenticação segura em aplicativos Spring Security, fornecendo funcionalidades essenciais para lidar com credenciais de usuários e garantindo a segurança da senha no armazenamento.

# Classe AuthenticationController

Essa classe representa um controlador (`AuthenticationController`) em uma aplicação Spring Boot com Spring Security. Este controlador lida com operações de autenticação, como login e registro de usuários. 

```java
package com.api.crud.controllers;

import com.api.crud.domain.user.AuthenticationDto;
import com.api.crud.domain.user.RegisterDto;
import com.api.crud.domain.user.User;
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

    // http://localhost:8080/auth/login
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Valid AuthenticationDto data){

       // Vale ressaltar que não é uma boa prática salvar o valor do password no BD, o correto é salvar o hash dessa senha (criptografia da senha).
       // Lembrando que as consultas também serão em hash.

       var userNamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password()); // Criando um objeto UsernamePasswordAuthenticationToken com as credenciais fornecidas (login e senha)
       var auth = this.authenticationManager.authenticate(userNamePassword); // Autenticando o usuário utilizando o AuthenticationManager

       return ResponseEntity.ok().build(); // Retornando uma resposta HTTP 200 OK se a autenticação for bem-sucedida
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
```

Principais características da classe:

1. **`@RestController` e `@RequestMapping("auth")`:**
   ```java
   @RestController
   @RequestMapping("auth")
   ```

   Essas anotações definem a classe `AuthenticationController` como um controlador REST que lida com requisições relacionadas à autenticação. O prefixo `/auth` especifica o caminho base para todos os endpoints definidos nesta classe.

2. **Injeção de Dependências:**
   ```java
   @Autowired
   private AuthenticationManager authenticationManager;

   @Autowired
   private UserRepository userRepository;
   ```

   Duas dependências são injetadas no controlador: `AuthenticationManager` e `UserRepository`. A primeira é necessária para realizar a autenticação dos usuários, enquanto a segunda é utilizada para acessar o banco de dados e realizar operações relacionadas aos usuários.

3. **Endpoint `/auth/login`:**
   ```java
   @PostMapping("/login")
   public ResponseEntity login(@RequestBody @Valid AuthenticationDto data){
       // ...
       return ResponseEntity.ok().build();
   }
   ```

   Este método trata requisições POST para o endpoint `/auth/login`. Ele recebe um objeto `AuthenticationDto` do corpo da requisição, que contém informações de login (como login e senha). O método utiliza o `AuthenticationManager` para autenticar o usuário através do `UsernamePasswordAuthenticationToken`. Se a autenticação for bem-sucedida, uma resposta `200 OK` é retornada. No entanto, neste exemplo, não está sendo retornado nenhum token ou informação de autenticação, o que seria necessário em uma aplicação real.

4. **Endpoint `/auth/register`:**
   ```java
   @PostMapping("/register")
   public ResponseEntity register(@RequestBody @Valid RegisterDto data){
       // ...
       return ResponseEntity.ok().build();
   }
   ```

   Este método trata requisições POST para o endpoint `/auth/register`. Ele recebe um objeto `RegisterDto` do corpo da requisição, que contém informações necessárias para registrar um novo usuário (como login, senha e role). O método verifica se já existe um usuário com o mesmo login no banco de dados. Se não houver, ele criptografa a senha usando o BCryptPasswordEncoder, cria uma nova instância de `User` e a salva no banco de dados usando o `UserRepository`. Uma resposta `200 OK` é retornada se o registro for bem-sucedido.

É importante notar que a prática de salvar senhas no banco de dados em texto plano não é segura. No entanto, neste exemplo, você está usando o BCryptPasswordEncoder para criptografar as senhas antes de armazená-las. Em um ambiente de produção, é altamente recomendável usar boas práticas de segurança, como armazenar apenas hashes de senhas devidamente seguros e utilizar HTTPS para proteger as informações durante a transmissão.

# Classe TokenService

Essa clase `TokenService` é responsável por gerar e validar tokens JWT (JSON Web Tokens).

```java
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
```

Analisando os principais métodos e funcionalidades dessa classe:

1. **`@Service`**:
   - A anotação `@Service` indica que esta classe é um componente de serviço gerenciado pelo contêiner de Inversão de Controle (IoC) do Spring. Essa anotação é comumente usada para classes que contêm lógica de negócios.

2. **`@Value("${api.security.token.secret}")`**:
   - A anotação `@Value` é usada para injetar o valor de uma propriedade configurada no arquivo `application.properties` ou `application.yml`.
   - Neste caso, o valor da propriedade `${api.security.token.secret}` é injetado na variável `secret`. Essa propriedade contém a chave secreta usada para assinar e verificar os tokens JWT.

3. **`generateToken(User user)`**:
   - Método responsável por gerar um token JWT com base nas informações do usuário.
   - Utiliza a biblioteca JWT (dependência externa) para criar o token.
   - O token inclui o emissor (`withIssuer`), o assunto (`withSubject` - normalmente o login do usuário), a data de expiração (`withExpiresAt`), e é assinado com a chave secreta.
   - Caso ocorra uma exceção durante a criação do token, uma exceção `RuntimeException` é lançada.

4. **`validateToken(String token)`**:
   - Método responsável por validar um token JWT.
   - Utiliza a biblioteca JWT para verificar a assinatura e extrair o assunto (normalmente o login do usuário) do token.
   - Caso ocorra uma exceção durante a validação do token, uma string vazia `""` é retornada.

5. **`genExpirationDate()`**:
   - Método privado que gera a data de expiração do token.
   - Neste caso, a data de expiração é definida como 2 horas a partir do momento atual. Isso é útil para garantir que os tokens tenham uma vida útil limitada.

Essa classe é um exemplo de implementação de serviços relacionados a tokens JWT em um contexto de autenticação e autorização. Tokens JWT são frequentemente utilizados para transmitir informações de identidade de forma segura entre o cliente e o servidor.

# Classes Algorithm e JWT

1. **`Algorithm`**:

   - A classe `Algorithm` faz parte da biblioteca `com.auth0:java-jwt`, que é frequentemente usada para trabalhar com tokens JWT em Java.
   - No contexto do código fornecido, `Algorithm.HMAC256(secret)` cria um objeto `Algorithm` que utiliza o algoritmo HMAC SHA-256 para assinar e verificar tokens. O parâmetro `secret` é a chave secreta usada no processo de assinatura.
   - O algoritmo HMAC (Hash-based Message Authentication Code) é uma técnica de assinatura que utiliza uma função de hash criptográfica e uma chave secreta para gerar uma assinatura que pode ser verificada pela parte receptora.

2. **`JWT`**:

   - A classe `JWT` é uma parte da mesma biblioteca mencionada anteriormente (`com.auth0:java-jwt`).
   - Ela fornece métodos para a criação e verificação de tokens JWT.
   - No método `JWT.create()` está iniciando o processo de criação de um novo token JWT.
   - No método `JWT.require(algorithm)` está iniciando o processo de verificação de um token JWT, fornecendo o algoritmo necessário para verificar a assinatura.
   - O método `withIssuer("auth-api")` define o emissor do token como "auth-api". O emissor é uma entidade que emite o token.
   - O método `withSubject(user.getLogin())` define o assunto do token como o login do usuário. O assunto geralmente representa o principal sobre o qual o token é emitido.
   - O método `withExpiresAt(genExpirationDate())` define a data de expiração do token usando o método `genExpirationDate()`, que retorna uma data duas horas no futuro.
   - O método `sign(algorithm)` é usado para assinar o token com o algoritmo especificado, resultando em uma String representando o token JWT.
   - O método `verify(token).getSubject()` é usado para verificar a assinatura do token e obter o assunto do token, que, neste caso, é interpretado como o login do usuário.

Essas classes simplificam significativamente a criação e verificação de tokens JWT, proporcionando uma maneira fácil e segura de trabalhar com autenticação e autorização baseadas em tokens em aplicações Java.

# Configuração Flexível da Chave Secreta para Tokens JWT 

A propriedade `secret` que está ligada à anotação `@Value("${api.security.token.secret}")` é uma maneira de injetar valores externos, neste caso, uma chave secreta, em uma classe gerenciada pelo Spring, como um componente de serviço.

A anotação `@Value("${api.security.token.secret}")` é uma característica do Spring Framework que permite injetar valores diretamente de propriedades de configuração ou do ambiente. Essa anotação é especialmente útil para injetar configurações externas sem a necessidade de alterar o código-fonte.

```java
@Service
public class TokenService {

    /* Classe para gerar os tokens */
    @Value("${api.security.token.secret}")
    private String secret;

    // restante do código
}
```

Quebrando a explicação:

- **`@Value("${api.security.token.secret}")`**:
   - `@Value` é uma anotação do Spring usada para injetar valores de propriedades.
   - `${api.security.token.secret}` é uma expressão SpEL (Spring Expression Language) que representa a chave da propriedade a ser injetada.
   - `api.security.token.secret` é a chave da propriedade configurada no arquivo `application.properties` ou `application.yml`.
   - A anotação `@Value` irá buscar o valor correspondente a `api.security.token.secret` no ambiente de execução do Spring (por exemplo, no arquivo de propriedades).

- **`private String secret;`**:
   - A declaração `private String secret;` é onde o valor injetado será armazenado na classe `TokenService`.
   - O valor da propriedade configurada será atribuído à variável `secret` durante a inicialização da classe pelo Spring IoC Container.

A ideia por trás disso é manter a chave secreta fora do código-fonte para que possa ser configurada externamente. Isso é importante para questões de segurança, pois a chave secreta é uma informação sensível e não deve ser exposta diretamente no código-fonte.

A propriedade `api.security.token.secret=${JWT_SECRET:my-secret-key}` está relacionada à anotação `@Value("${api.security.token.secret}")` e ao atributo `private String secret;` da classe `TokenService`. Vamos entender o que cada parte dessa configuração faz:

```properties
api.security.token.secret=${JWT_SECRET:my-secret-key}
```

- **`api.security.token.secret=${JWT_SECRET:my-secret-key}`**:
   - `api.security.token.secret` é a chave da propriedade configurada no arquivo `application.properties` ou `application.yml`.
   - `${JWT_SECRET:my-secret-key}` é uma expressão que utiliza o formato `${property:defaultValue}`.
   - `JWT_SECRET` é um nome de variável de ambiente (ou propriedade do sistema) que o Spring procura para substituir o valor da propriedade.
   - Se a variável de ambiente `JWT_SECRET` estiver definida, o valor será substituído por ela; caso contrário, será utilizado o valor padrão `my-secret-key`.

- **`private String secret;`** (na classe `TokenService`):
   - A declaração `private String secret;` é onde o valor injetado será armazenado na classe `TokenService`.
   - Durante a inicialização da classe pelo Spring IoC Container, o valor da propriedade configurada será atribuído à variável `secret`.

Dessa forma, a configuração proporciona uma maneira flexível de definir a chave secreta utilizada na classe `TokenService`. Se a variável de ambiente `JWT_SECRET` estiver definida no ambiente em que a aplicação está sendo executada, essa será a chave secreta utilizada. Caso contrário, a chave padrão `my-secret-key` será usada.

Essa abordagem é útil em ambientes onde a configuração pode variar, permitindo que a aplicação seja configurada de forma diferente em diferentes ambientes (por exemplo, desenvolvimento, teste e produção) sem a necessidade de modificar o código-fonte.

# Classe SecurityFilter

Esta classe é um filtro de segurança (`SecurityFilter`) que estende a classe `OncePerRequestFilter` do Spring Security.

```java
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
```

Explicações para cada parte do código:

1. **`@Component`**:
   - A anotação `@Component` indica que a classe `SecurityFilter` é um componente gerenciado pelo contêiner Spring IoC (Inversão de Controle). Isso permite que o Spring o gerencie, injetando as dependências necessárias (anotadas com `@Autowired`) e integrando-o no fluxo de segurança da aplicação.

2. **`extends OncePerRequestFilter`**:
   - A classe `SecurityFilter` estende `OncePerRequestFilter`, que é uma classe do Spring Security que garante que o filtro seja executado apenas uma vez por cada solicitação HTTP.

3. **Injeção de Dependências**:
   - As anotações `@Autowired` são usadas para injetar instâncias de `TokenService` e `UserRepository` na classe. Isso é feito automaticamente pelo Spring IoC Container.

4. **`doFilterInternal`**:
   - Este é o método principal do filtro, onde a lógica de filtragem é implementada.
   - `doFilterInternal` é chamado para cada solicitação HTTP.
   - Ele recupera o token do cabeçalho da solicitação, valida o token usando o `TokenService`, e, se válido, recupera as informações do usuário do banco de dados usando o `UserRepository`.
   - Cria uma instância de `UsernamePasswordAuthenticationToken` com base nas informações do usuário e a define no contexto de segurança usando `SecurityContextHolder`. Isso é feito para que o Spring Security tenha conhecimento sobre a autenticação do usuário.
   - O método `filterChain.doFilter(request, response)` continua o processamento da solicitação, permitindo que ela siga seu curso normal após o tratamento do filtro.

5. **`recoverToken`**:
   - Método privado para recuperar o token do cabeçalho da solicitação.
   - Extrai o token do cabeçalho "Authorization" e remove a parte "Bearer ", deixando apenas o token JWT.

Essencialmente, este filtro atua na validação do token JWT presente nas solicitações HTTP, autenticando o usuário associado ao token e configurando o contexto de segurança para que o Spring Security possa lidar adequadamente com as autorizações subsequentes. Isso é útil em cenários onde a autenticação é baseada em tokens JWT.

# Classe OncePerRequestFilter e SecurityContextHolder

### `OncePerRequestFilter`:

A classe `OncePerRequestFilter` é uma classe fornecida pelo Spring Security que garante que o método `doFilterInternal` seja chamado apenas uma vez por cada solicitação HTTP. Isso é útil para casos em que deseja garantir que o filtro seja executado uma vez, independentemente do número de filtros ou interceptadores que estão no caminho da solicitação.

A assinatura da classe é a seguinte:

```java
public abstract class OncePerRequestFilter extends GenericFilterBean
```

### Método `doFilterInternal`:

O método `doFilterInternal` é o ponto de entrada principal para a lógica de filtragem. Aqui, implementa a lógica específica que deseja executar para cada solicitação HTTP. A assinatura do método é a seguinte:

```java
protected abstract void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException;
```

- `HttpServletRequest request`: Representa a solicitação HTTP recebida pelo servidor.
- `HttpServletResponse response`: Representa a resposta HTTP que será enviada de volta ao cliente.
- `FilterChain filterChain`: Representa a cadeia de filtros que será percorrida. Após a execução do método `doFilterInternal`, você geralmente chama `filterChain.doFilter(request, response)` para permitir que a solicitação continue seu processamento.

### `SecurityContextHolder`:

A classe `SecurityContextHolder` é uma parte fundamental do Spring Security. Ela armazena e fornece acesso ao contexto de segurança da aplicação. O contexto de segurança contém informações sobre a autenticação e autorização do usuário.

`SecurityContextHolder` fornece métodos estáticos para obter e definir o contexto de segurança. `getContext()` retorna o contexto de segurança atual, enquanto `setContext()` permite definir um novo contexto.

Exemplo de uso:

```java
SecurityContextHolder.getContext().setAuthentication(authentication);
```

Este código define a autenticação (`authentication`) no contexto de segurança atual, permitindo que o Spring Security saiba quem está autenticado.

Em resumo, `OncePerRequestFilter` é uma classe útil para criar filtros no Spring Security, e `SecurityContextHolder` é crucial para gerenciar o contexto de segurança da aplicação. O método `doFilterInternal` é onde implementa a lógica específica do filtro para cada solicitação HTTP.

---

# Autor
## Feito por: `Daniel Penelva de Andrade`