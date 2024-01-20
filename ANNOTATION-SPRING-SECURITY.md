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

--- 

# Autor
## Feito por: `Daniel Penelva de Andrade`