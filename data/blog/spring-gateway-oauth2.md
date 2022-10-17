---
title: 将Spring Cloud Gateway 与OAuth2模式一起使用
date: 2022-08-13 12:07:52
tags: ['OAuth2', 'SpringSecurity']
draft: false
authors: ['default']
---

## 将Spring Cloud Gateway 与OAuth2模式一起使用



### 概述

Spring Cloud Gateway是一个构建在 Spring 生态之上的 API Gateway。 建立在 [Spring Boot 2.x](https://spring.io/projects/spring-boot#learn) 、[Spring WebFlux](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) 和 [Project Reactor](https://projectreactor.io/docs) 之上。



本节中您将使用Spring Cloud Gateway将请求路由到Servlet API服务。

**本文您将学到**：

- OpenID Connect 身份验证 - 用于用户身份验证
- 令牌中继 - Spring Cloud Gateway API网关充当客户端将令牌转发到资源请求上



**先决条件**：

- Java 8+
- MySQL
- Redis





### OpenID Connect身份验证

OpenID Connect 定义了一种基于 OAuth2 授权代码流的最终用户身份验证机制。下图是Spring Cloud Gateway与授权服务进行身份验证完整流程，为了清楚起见，其中一些参数已被省略。

![](../static/images/blogs/spring-gateway-oauth2.drawio.png)



### 创建授权服务

本节中我们将使用[Spring Authorization Server](https://spring.io/projects/spring-authorization-server#overview) 构建授权服务，支持OAuth2协议与OpenID Connect协议。同时我们还将使用RBAC0基本权限模型控制访问权限。并且该授权服务同时作为OAuth2客户端支持Github第三方登录。



<br />

#### 相关数据库表结构

我们创建了基本RBAC0权限模型用于本文示例讲解，并提供了OAuth2授权服务持久化存储所需表结构和OAuth2客户端持久化存储所需表结构。通过oauth2_client_role定义外部系统角色与本平台角色映射关系。涉及相关创建表及初始化数据的SQL语句可以[从这里](https://github.com/ReLive27/spring-security-oauth2-sample/tree/main/gateway-oauth2-login/auth-server/src/main/resources/db/migration)获取。

![](../static/images/blogs/spring-gateway-oauth2-db.png)



#### 角色说明

本节中授权服务默认提供两个角色，以下是角色属性及访问权限：

|                | read | write |
| :------------- | :---- | :---- |
| ROLE_ADMIN     | ✅    | ✅     |
| ROLE_OPERATION | ✅    | ❎     |



#### Maven依赖

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-oauth2-authorization-server</artifactId>
  <version>0.3.1</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-client</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-web</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-jdbc</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-jpa</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>mysql</groupId>
  <artifactId>mysql-connector-java</artifactId>
  <version>8.0.21</version>
</dependency>
<dependency>
  <groupId>com.alibaba</groupId>
  <artifactId>druid-spring-boot-starter</artifactId>
  <version>1.2.3</version>
</dependency>
```





#### 配置

首先我们从application.yml配置开始，这里我们指定了端口号与MySQL连接配置：

```yaml
server:
  port: 8080

spring:
  datasource:
    druid:
      db-type: mysql
      driver-class-name: com.mysql.cj.jdbc.Driver
      url: jdbc:mysql://localhost:3306/oauth2server?createDatabaseIfNotExist=true&useUnicode=true&characterEncoding=UTF-8&useSSL=false&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true
      username: <<username>> # 修改用户名
      password: <<password>> # 修改密码
```

<br />

接下来我们将创建`AuthorizationServerConfig`，用于配置OAuth2及OIDC所需Bean，首先我们将新增OAuth2客户端信息，并持久化到数据库：

```java
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        RegisteredClient registeredClient = RegisteredClient.withId("relive-messaging-oidc")
                .clientId("relive-client")
                .clientSecret("{noop}relive-client")
                .clientAuthenticationMethods(s -> {
                    s.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                    s.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                })
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8070/login/oauth2/code/messaging-gateway-oidc")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("read")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false) //不需要授权同意
                        .requireProofKey(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // 生成JWT令牌
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .accessTokenTimeToLive(Duration.ofSeconds(30 * 60))//accessTokenTimeToLive：access_token有效期
                        .refreshTokenTimeToLive(Duration.ofSeconds(60 * 60))//refreshTokenTimeToLive：refresh_token有效期
                        .reuseRefreshTokens(true)
                        .build())
                .build();

        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        registeredClientRepository.save(registeredClient);
        return registeredClientRepository;
    }

```

<br />



其次我们将创建授权过程中所需持久化容器类：

```java
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

 
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }
```

<br />

授权服务器需要其用于令牌的签名密钥，让我们生成一个 2048 字节的 RSA 密钥：

```java
@Bean
public JWKSource<SecurityContext> jwkSource() {
  RSAKey rsaKey = Jwks.generateRsa();
  JWKSet jwkSet = new JWKSet(rsaKey);
  return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
}

static class Jwks {

  private Jwks() {
  }

  public static RSAKey generateRsa() {
    KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
      .privateKey(privateKey)
      .keyID(UUID.randomUUID().toString())
      .build();
  }
}

static class KeyGeneratorUtils {

  private KeyGeneratorUtils() {
  }

  static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }
}
```

<br />

接下来我们将创建用于OAuth2授权的`SecurityFilterChain`，SecurityFilterChain是Spring Security提供的过滤器链，Spring Security的认证授权功能都是通过滤器完成：

```java
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        //配置OIDC
        authorizationServerConfigurer.oidc(Customizer.withDefaults());

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        return http.requestMatcher(endpointsMatcher)
                .authorizeRequests((authorizeRequests) -> {
                    ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl) authorizeRequests.anyRequest()).authenticated();
                }).csrf((csrf) -> {
                    csrf.ignoringRequestMatchers(new RequestMatcher[]{endpointsMatcher});
                }).apply(authorizationServerConfigurer)
                .and()
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .exceptionHandling(exceptions -> exceptions.
                        authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .apply(authorizationServerConfigurer)
                .and()
                .build();
    }
```

上述我们配置了OAuth2和OpenID Connect默认配置，并将为认证请求重定向到登录页，同时我们还启用了Spring Security提供的OAuth2资源服务配置，该配置用于保护OpenID Connect中/userinfo用户信息端点。

<br />

在启用Spring Security的OAuth2资源服务配置时我们指定了JWT验证，所以我们需要在application.yml中指定jwk-set-uri或声明式添加`JwtDecoder`，下面我们使用声明式配置：

```java
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
```

<br />

接下来我们将自定义Access Token，在本示例中我们使用RBAC0权限模型，所以我们在Access Token中添加`authorities`为当前用户所属角色的权限(permissionCode)：

```java
@Configuration(proxyBeanMethods = false)
public class AccessTokenCustomizerConfig {

    @Autowired
    RoleRepository roleRepository;

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claims(claim -> {
                    claim.put("authorities", roleRepository.findByRoleCode(context.getPrincipal().getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority).findFirst().orElse("ROLE_OPERATION"))
                            .getPermissions().stream().map(Permission::getPermissionCode).collect(Collectors.toSet()));
                });
            }
        };
    }
}

```



> RoleRepository属于role表持久层对象，在本示例中选用JPA框架，相关代码将不在文中展示，如果您并不了解JPA使用，可以使用Mybatis替代。



<br />

下面我们将配置授权服务Form表单认证方式：

```java
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .formLogin(withDefaults())
                
          ...
          
        return http.build();
    }
```

<br />

接下来我们将创建*JdbcUserDetailsService* 实现 *UserDetailsService*，用于在认证过程中查找登录用户的密码及权限信息，至于为什么需要实现*UserDetailsService*，感兴趣可以查看UsernamePasswordAuthenticationFilter -> ProviderManager -> DaoAuthenticationProvider 源码，在DaoAuthenticationProvider中通过调用UserDetailsService#loadUserByUsername(String username)获取用户信息。

```java
@RequiredArgsConstructor
public class JdbcUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.relive.entity.User user = userRepository.findUserByUsername(username);
        if (ObjectUtils.isEmpty(user)) {
            throw new UsernameNotFoundException("user is not found");
        }
        if (CollectionUtils.isEmpty(user.getRoleList())) {
            throw new UsernameNotFoundException("role is not found");
        }
        Set<SimpleGrantedAuthority> authorities = user.getRoleList().stream().map(Role::getRoleCode)
                .map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        return new User(user.getUsername(), user.getPassword(), authorities);
    }
}

```

并将它注入到Spring中：

```java
    @Bean
    UserDetailsService userDetailsService(UserRepository userRepository) {
        return new JdbcUserDetailsService(userRepository);
    }
```



<br />

在尝试请求未认证接口将会引导用户到登录页面并提示输入用户名密码，结果如下：

![](../static/images/blogs/spring-gateway-oauth2-login-page.png)

<br />

<br />

用户通常需要使用多个平台，这些平台由不同组织提供和托管。 这些用户可能需要使用每个平台的特定（和不同）的凭据。当用户拥有许多不同的凭据时，他们常常会忘记登录凭据。

**联合身份验证**是使用外部系统对用户进行身份验证。这可以与Google，Github或任何其他身份提供商一起使用。在这里，我将使用Github进行用户身份验证和数据同步管理。



#### Github身份认证

首先我们将配置Github客户端信息，你只需要更改其中**clientId**和**clientSecret**。其次我们将使用[Spring Security 持久化OAuth2客户端](https://relive27.github.io/blog/persisrence-oauth2-client) 文中介绍的*JdbcClientRegistrationRepository*持久层容器类将GitHub客户端信息存储在数据库中：

```java
    @Bean
    ClientRegistrationRepository clientRegistrationRepository(JdbcTemplate jdbcTemplate) {
        JdbcClientRegistrationRepository jdbcClientRegistrationRepository = new JdbcClientRegistrationRepository(jdbcTemplate);
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("github")
                .clientId("123456")
                .clientSecret("123456")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
                .scope(new String[]{"read:user"})
                .authorizationUri("https://github.com/login/oauth/authorize")
                .tokenUri("https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .userNameAttributeName("login")
                .clientName("GitHub").build();

        jdbcClientRegistrationRepository.save(clientRegistration);
        return jdbcClientRegistrationRepository;
    }
```

<br />

接下来我们将实例化*OAuth2AuthorizedClientService*和*OAuth2AuthorizedClientRepository*：

- **OAuth2AuthorizedClientService**：负责OAuth2AuthorizedClient在 Web 请求之间进行持久化。
- **OAuth2AuthorizedClientRepository**：用于在请求之间保存和持久化授权客户端。

```java

    @Bean
    OAuth2AuthorizedClientService authorizedClientService(
            JdbcTemplate jdbcTemplate,
            ClientRegistrationRepository clientRegistrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository);
    }

    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }
```



<br />

对于每个使用Github登录的用户，我们都要分配平台的角色以控制他们可以访问哪些资源，在此我们将新建*AuthorityMappingOAuth2UserService*类授予用户角色：



```java
@RequiredArgsConstructor
public class AuthorityMappingOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    private final OAuth2ClientRoleRepository oAuth2ClientRoleRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        DefaultOAuth2User oAuth2User = (DefaultOAuth2User) delegate.loadUser(userRequest);

        Map<String, Object> additionalParameters = userRequest.getAdditionalParameters();
        Set<String> role = new HashSet<>();
        if (additionalParameters.containsKey("authority")) {
            role.addAll((Collection<? extends String>) additionalParameters.get("authority"));
        }
        if (additionalParameters.containsKey("role")) {
            role.addAll((Collection<? extends String>) additionalParameters.get("role"));
        }
        Set<SimpleGrantedAuthority> mappedAuthorities = role.stream()
                .map(r -> oAuth2ClientRoleRepository.findByClientRegistrationIdAndRoleCode(userRequest.getClientRegistration().getRegistrationId(), r))
                .map(OAuth2ClientRole::getRole).map(Role::getRoleCode).map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        //当没有指定客户端角色，则默认赋予最小权限ROLE_OPERATION
        if (CollectionUtils.isEmpty(mappedAuthorities)) {
            mappedAuthorities = new HashSet<>(
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_OPERATION")));
        }
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        return new DefaultOAuth2User(mappedAuthorities, oAuth2User.getAttributes(), userNameAttributeName);
    }
}
```

我们可以看到从`authority`和`role`属性中获取权限信息，在通过OAuth2ClientRoleRepository查找映射到本平台的角色属性。

> 注意：`authority`和`role`是由平台自定义属性，与OAuth2协议与Open ID Connect 协议无关，在生产环境中你可以与外部系统协商约定一个属性来传递权限信息。
>
> OAuth2ClientRoleRepository为`oauth2_client_role`表持久层容器类，由JPA实现。

对于未获取到预先定义的映射角色信息，我们将赋予默认`ROLE_OPERATION`最小权限角色。而在本示例中GitHub登录的用户来说，也将被赋予`ROLE_OPERATION`角色。



<br />

针对GitHub认证成功并且首次登录的用户我们将获取用户信息并持久化到`user`表中,这里我们实现AuthenticationSuccessHandler并增加持久化用户逻辑：

```java
public final class SavedUserAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();


    private Consumer<OAuth2User> oauth2UserHandler = (user) -> {
    };

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            if (authentication.getPrincipal() instanceof OAuth2User) {
                this.oauth2UserHandler.accept((OAuth2User) authentication.getPrincipal());
            }
        }

        this.delegate.onAuthenticationSuccess(request, response, authentication);
    }

    public void setOauth2UserHandler(Consumer<OAuth2User> oauth2UserHandler) {
        this.oauth2UserHandler = oauth2UserHandler;
    }
}
```

我们将通过`setOauth2UserHandler(Consumer<OAuth2User> oauth2UserHandler)`方法将*UserRepositoryOAuth2UserHandler*注入到*SavedUserAuthenticationSuccessHandler*中，UserRepositoryOAuth2UserHandler定义了具体持久层操作：

```java
@Component
@RequiredArgsConstructor
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    @Override
    public void accept(OAuth2User oAuth2User) {
        DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) oAuth2User;
        if (this.userRepository.findUserByUsername(oAuth2User.getName()) == null) {
            User user = new User();
            user.setUsername(defaultOAuth2User.getName());
            Role role = roleRepository.findByRoleCode(defaultOAuth2User.getAuthorities()
                    .stream().map(GrantedAuthority::getAuthority).findFirst().orElse("ROLE_OPERATION"));
            user.setRoleList(Arrays.asList(role));
            userRepository.save(user);
        }
    }
}
```

我们通过defaultOAuth2User.getAuthorities()获取到映射后的角色信息，并将其与用户信息存储到数据库中。

> UserRepository和RoleRepository为持久化容器类。



<br />

最后我们向SecurityFilterChain加入OAuth2 Login配置：

```java
    @Autowired
    UserRepositoryOAuth2UserHandler userHandler;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .oauth2Login(oauth2login -> {
                    SavedUserAuthenticationSuccessHandler successHandler = new SavedUserAuthenticationSuccessHandler();
                    successHandler.setOauth2UserHandler(userHandler);
                    oauth2login.successHandler(successHandler);
                });
      
      	...
        
        return http.build();
    }
```









### 创建Spring Cloud Gateway应用程序

本节中我们将在Spring Cloud Gateway中通过[Spring Security OAuth2 Login](https://docs.spring.io/spring-security/reference/reactive/oauth2/login/index.html) 启用OpenID Connect身份验证，并将Access Token中继到下游服务。

#### Maven依赖

```xml
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-gateway</artifactId>
  <version>3.1.2</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-client</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-redis</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.session</groupId>
  <artifactId>spring-session-data-redis</artifactId>
  <version>2.6.3</version>
</dependency>

<dependency>
  <groupId>io.netty</groupId>
  <artifactId>netty-all</artifactId>
  <version>4.1.76.Final</version>
</dependency>

```





#### 配置

首先我们在application.yml添加以下属性：

```yaml
server:
  port: 8070
  servlet:
    session:
      cookie:
        name: GATEWAY-CLIENT
```

这里指定了cookie name为`GATEWAY-CLIENT`，避免与授权服务`JSESSIONID`冲突。

<br />

通过Spring Cloud Gateway路由到资源服务器：

```yaml
spring:
  cloud:
    gateway:
      discovery:
        locator:
          enabled: true
      routes:
        - id: resource-server
          uri: http://127.0.0.1:8090
          predicates:
            Path=/resource/**
          filters:
            - TokenRelay

```

TokenRelay 过滤器将提取存储在用户会话中的访问令牌，并将其作为`Authorization`标头添加到传出请求中。这允许下游服务对请求进行身份验证。



<br />

我们将在application.yml中添加OAuth2客户端信息：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          messaging-gateway-oidc:
            provider: gateway-client-provider
            client-id: relive-client
            client-secret: relive-client
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            scope:
              - openid
              - profile
            client-name: messaging-gateway-oidc
        provider:
          gateway-client-provider:
            authorization-uri: http://127.0.0.1:8080/oauth2/authorize
            token-uri: http://127.0.0.1:8080/oauth2/token
            jwk-set-uri: http://127.0.0.1:8080/oauth2/jwks
            user-info-uri: http://127.0.0.1:8080/userinfo
            user-name-attribute: sub
```

OpenID Connect 使用一个特殊的权限范围值 openid 来控制对 UserInfo 端点的访问，其他信息与上节中授权服务注册客户端信息参数保持一致。



<br />

我们通过Spring Security拦截未认证请求到授权服务器进行认证。为了简单起见，[CSRF](https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/csrf.html)被禁用。

```java
@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
public class OAuth2LoginSecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(authorize -> authorize
                        .anyExchange().authenticated()
                )
                .oauth2Login(withDefaults())
                .cors().disable();
        return http.build();
    }
}
```



<br />

Spring Cloud Gateway在完成OpenID Connect身份验证后，将用户信息和令牌存储在session会话中，所以添加`spring-session-data-redis`提供由 Redis 支持的分布式会话功能，在`application.yml`中添加以下配置：

```yaml
spring:
  session:
    store-type: redis # 会话存储类型
    redis:
      flush-mode: on_save # 会话刷新模式
      namespace: gateway:session # 用于存储会话的键的命名空间
  redis:
    host: localhost
    port: 6379
    password: 123456
```





<br />

基于上述示例我们使用 Spring Cloud Gateway驱动身份验证，知道如何对用户进行身份验证，可以为用户获取令牌（在用户同意后），但不对通过Gateway的请求进行身份验证/授权（Spring Gateway Cloud并不是Access Token的受众目标）。这种方法背后的原因是一些服务是受保护的，而一些是公共的。即使在单个服务中，有时也只能保护几个端点而不是每个端点。这就是我将请求的身份验证/授权留给特定服务的原因。

当然从实现角度并不妨碍我们在Spring Cloud Gateway进行身份验证/授权，这只是一个选择问题。





### 搭建资源服务

本节中我们使用Spring Boot搭建一个简单的资源服务，示例中资源服务提供两个API接口，并通过Spring Security OAuth2资源服务配置保护。



#### Maven依赖

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-web</artifactId>
  <version>2.6.7</version>
</dependency>
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
  <version>2.6.7</version>
</dependency>
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
  <version>2.6.7</version>
</dependency>
```





#### 配置

在`application.yml`中添加`jwk-set-uri`属性：

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://127.0.0.1:8080
          jwk-set-uri: http://127.0.0.1:8080/oauth2/jwks 

server:
  port: 8090
```

<br />

创建`ResourceServerConfig`类来配置Spring Security安全模块，`@EnableMethodSecurity`注解来启用基于注解的安全性：

```java
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize
                .anyRequest().authenticated()
                 )
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }
}
```

<br />



Spring Security资源服务在验证token提取权限默认使用claim中`scope`和`scp`属性。

> Spring Security `JwtAuthenticationProvider`通过`JwtAuthenticationConverter`辅助转换器提取权限等信息。

但是在本示例中内部化权限使用`authorities`属性，所以我们使用*JwtAuthenticationConverter* 手动提取权限：

```java
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
        grantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }
```

在这里我们将权限属性指定为`authorities`，并完全删除权限前缀。

<br />



最后我们将创建用于示例中测试的API接口，使用`@PreAuthorize`保护接口必须由相应权限才能访问：

```java
@RestController
public class ArticleController {

    List<String> article = new ArrayList<String>() {{
        add("article1");
        add("article2");
    }};

    @PreAuthorize("hasAuthority('read')")
    @GetMapping("/resource/article/read")
    public Map<String, Object> read(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> result = new HashMap<>(2);
        result.put("principal", jwt.getClaims());
        result.put("article", article);
        return result;
    }

    @PreAuthorize("hasAuthority('write')")
    @GetMapping("/resource/article/write")
    public String write(@RequestParam String name) {
        article.add(name);
        return "success";
    }
}
```



### 测试我们的应用程序

在我们启动完成服务后，我们在浏览器中访问[http://127.0.0.1:8070/resource/article/read](http://127.0.0.1:8070/resource/article/read) ,我们将重定向到授权服务登录页，如图所示：

![](../static/images/blogs/spring-gateway-oauth2-login.png)



<br />

在我们输入用户名密码（admin/password）后，将获取到请求响应信息：

![](../static/images/blogs/spring-gateway-oauth2-response1.png)



<br />

admin用户所属角色是`ROLE_ADMIN`，所以我们尝试请求[http://127.0.0.1:8070/resource/article/write?name=article3](http://127.0.0.1:8070/resource/article/write?name=article3)

![](../static/images/blogs/spring-gateway-oauth2-response2.png)



<br />

注销登录后，我们同样访问[http://127.0.0.1:8070/resource/article/read](http://127.0.0.1:8070/resource/article/read) ，不过这次使用Github登录，响应信息如图所示：

![](../static/images/blogs/spring-gateway-oauth2-response3.png)

可以看到响应信息中用户已经切换为你的Github用户名。



<br />

Github登录的用户默认赋予角色为`ROLE_OPERATION`,而`ROLE_OPERATION`是没有[http://127.0.0.1:8070/resource/article/write?name=article3](http://127.0.0.1:8070/resource/article/write?name=article3 ) 访问权限，我们来尝试测试下: 

![](../static/images/blogs/spring-gateway-oauth2-response4.png)



结果我们请求被拒绝，403状态码提示我们没有访问权限。





### 结论

本文中您了解到如何使用Spring Cloud Gateway结合OAuth2保护微服务。在示例中浏览器cookie仅存储sessionId，JWT访问令牌并没有暴露给浏览器，而是在内部服务中流转。这样我们体验到了JWT带来的优势，也同样利用cookie-session弥补了JWT的不足，例如当我们需要实现强制用户登出功能。

与往常一样，本文中使用的源代码可[在 GitHub 上](https://github.com/ReLive27/spring-security-oauth2-sample/tree/main/gateway-oauth2-login)获得。
