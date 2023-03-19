---
title: Spring Security和OpenID Connect
date: 2022-08-01 20:35:28
tags: ['OAuth2', 'SpringSecurity']
draft: false
authors: ['default']
---

## Spring Security和OpenID Connect



### 概述

OpenID Connect 是一个开放标准，由 OpenID 基金会于 2014 年 2 月发布。它定义了一种使用 OAuth 2.0 执行用户身份认证的互通方式。OpenID Connect 直接基于 OAuth 2.0 构建，并保持与它兼容。

当授权服务器支持 OIDC 时，它有时被称为*身份提供者（Idp）*，因为它向**客户端**提供有关**资源所有者**的信息。而**客户端**映射为OpenID Connect 流程中*登录依赖方（RP）*。在本文中我们将授权服务称为身份提供者，客户端称为登录依赖方进行陈述。



OpenID Connect 流程看起来与 OAuth 相同。主要区别是，在授权请求中，使用了一个特定的范围`openid`，而在获取token中，**登录依赖方（RP）**同时接收到一个**访问令牌**和一个**ID 令牌**（经过签名的 JWT）。ID令牌与访问令牌不同的是，ID 令牌是发送给 RP 的，并且要被它解析。



**本文您将学到**：

- 配置授权服务支持OpenID Connect
- 自定义ID令牌
- 登录依赖方通过`OAuth2UserService`实现权限映射



**先决条件：**

- java 8+
- mysql



### 使用Spring Authorization Server搭建身份提供服务(IdP)

本节中我们将使用[Spring Authorization Server](https://spring.io/projects/spring-authorization-server) 搭建身份提供服务，并通过`OAuth2TokenCustomizer` 实现自定义ID Token。

#### maven 依赖项

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
  <artifactId>spring-boot-starter-web</artifactId>
  <version>2.6.7</version>
</dependency>
```



#### 配置

首先我们配置身份提供服务端口8080:

```yaml
server:
  port: 8080
```



接下来我们创建`AuthorizationServerConfig`配置类，在此类中我们配置OAuth2及OICD相关Bean。我们首先注册一个客户端：

```java
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("relive-client")
                .clientSecret("{noop}relive-client")
                .clientAuthenticationMethods(s -> {
                    s.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                    s.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                })
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8070/login/oauth2/code/messaging-client-oidc")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .accessTokenTimeToLive(Duration.ofSeconds(30 * 60))
                        .refreshTokenTimeToLive(Duration.ofSeconds(60 * 60))
                        .reuseRefreshTokens(true)
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }
```

我们正在配置的属性是：

- clientId —— 身份提供服务将使用它来识别哪个客户端正在尝试访问资源
- clientSecret——客户端和服务器都知道的一个秘密，它提供了两者之间的信任
- clientAuthenticationMethod——客户端验证方式，在我们的例子中，我们将支持basic和post身份验证方式
- authorizationGrantType——授权类型，支持授权码和刷新令牌
- redirectUri —— 重定向 URI，客户端将在基于重定向的流程中使用它
- scope——此参数定义客户端可能拥有的权限。在我们的例子中，我们将拥有所需的`openid`和用来获取额外的*身份*信息`profile`，`email`。

<br />

OpenID Connect 使用一个特殊的权限范围值 openid 来控制对 UserInfo 端点的访问。 OpenID Connect 定义了一组标准化的 OAuth 权限范围，对应于用户属性的子集profile、email、 phone、address，参见表格：



| 权限范围   | 声明                                                         |
| ---------- | :----------------------------------------------------------- |
| **openid** | **sub**                                                      |
| profile    | Name、family_name、given_name、middle_name、nickname、preferred_username、profile、 picture、website、gender、birthdate、zoneinfo、locale、updated_at |
| email      | email、email_verified                                        |
| address    | address,是一个 JSON 对象、包含 formatted、street_address、locality、region、postal_code、country |
| phone      | phone_number、phone_number_verified                          |

让我们根据上述规范定义`OidcUserInfoService`，用于扩展/userinfo用户信息端点响应：

```java
public class OidcUserInfoService {

    public OidcUserInfo loadUser(String name, Set<String> scopes) {
        OidcUserInfo.Builder builder = OidcUserInfo.builder().subject(name);
        if (!CollectionUtils.isEmpty(scopes)) {
            if (scopes.contains(OidcScopes.PROFILE)) {
                builder.name("First Last")
                        .givenName("First")
                        .familyName("Last")
                        .middleName("Middle")
                        .nickname("User")
                        .preferredUsername(name)
                        .profile("http://127.0.0.1:8080/" + name)
                        .picture("http://127.0.0.1:8080/" + name + ".jpg")
                        .website("http://127.0.0.1:8080/")
                        .gender("female")
                        .birthdate("2022-05-24")
                        .zoneinfo("China/Beijing")
                        .locale("zh-cn")
                        .updatedAt(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE));
            }
            if (scopes.contains(OidcScopes.EMAIL)) {
                builder.email(name + "@163.com").emailVerified(true);
            }
            if (scopes.contains(OidcScopes.ADDRESS)) {
                JSONObject address = new JSONObject();
                address.put("address", Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"));
                builder.address(address.toJSONString());
            }
            if (scopes.contains(OidcScopes.PHONE)) {
                builder.phoneNumber("13728903134").phoneNumberVerified("false");
            }
        }
        return builder.build();
    }
}

```



<br />

接下来，我们将配置一个 bean 以应用默认 OAuth 安全性。使用上述`OidcUserInfoService`配置OIDC中UserInfoMapper；oauth2ResourceServer()配置资源服务器使用JWT验证，用来保护身份提供服务的/userinfo端点；对于未认证请求我们会将它重定向到/login 登录页：

> 注意：有时“授权服务器”和“资源服务器”是同一台服务器。



```java
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();

        //自定义用户映射器
        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
            return userInfoService.loadUser(principal.getName(), context.getAccessToken().getScopes());
        };
        authorizationServerConfigurer.oidc((oidc) -> {
            oidc.userInfoEndpoint((userInfo) -> userInfo.userInfoMapper(userInfoMapper));
        });

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        return http.requestMatcher(endpointsMatcher).authorizeRequests((authorizeRequests) -> {
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



<br />

每个授权服务器都需要其用于令牌的签名密钥，让我们生成一个 2048 字节的 RSA 密钥：

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

然后我们将使用带有`@EnableWebSecurity`注释的配置类启用 Spring Web 安全模块：

```java
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .formLogin(withDefaults());
        return http.build();
    }

    //...
}

```

这里我们使用Form认证方式，所以我们还需要为登录认证提供用户名和密码：

```java
    @Bean
    UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
```



<br />

至此，我们服务配置完成，但是用于给客户端传递权限信息，我们将更改`ID Token` claim，添加用户角色属性：

```java
@Configuration(proxyBeanMethods = false)
public class IdTokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                context.getClaims().claims(claims ->
                        claims.put("role", context.getPrincipal().getAuthorities()
                                .stream().map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toSet())));
            }
        };
    }
}
```





### 登录依赖方服务（RP）实现

本节中我们将使用Spring Security搭建登录依赖方服务，并设计相关数据库表结构表达关联身份提供方服务与登录依赖方服务权限关系，通过`OAuth2UserService`实现权限映射。

本节中部分代码涉及JPA相关知识，如果您并不了解也没有关系，您可以通过Mybatis进行替换。

#### maven 依赖项

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-web</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-client</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-jdbc</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-jpa</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-thymeleaf</artifactId>
  <version>2.6.7</version>
</dependency>

<dependency>
  <groupId>mysql</groupId>
  <artifactId>mysql-connector-java</artifactId>
  <version>8.0.21</version>
</dependency>
```



#### 相关数据库表结构

这是我们本文中RP服务使用的相关数据库表，涉及相关创建表及初始化数据的SQL语句可以[从这里](https://github.com/ReLive27/spring-security-oauth2-sample/tree/main/oidc-login/rp/src/main/resources/db/migration) 获取。

![](../static/images/blogs/spring-oidc-sql-model.png)



#### 配置

首先我们通过`application.yml`文件中配置服务端口和数据库连接信息：

```yaml
server:
  port: 8070
  servlet:
    session:
      cookie:
        name: CLIENT-SESSION

spring:
  datasource:
    druid:
      db-type: mysql
      driver-class-name: com.mysql.cj.jdbc.Driver
      url: jdbc:mysql://localhost:3306/oidc_login?createDatabaseIfNotExist=true&useUnicode=true&characterEncoding=UTF-8&useSSL=false&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true
      username: <<root>> # 修改用户名
      password: <<password>> # 修改密码
```



<br />

接下来我们将启用Spring Security安全配置。使用Form认证方式；并使用*oauth2Login*()定义OAuth2登录默认配置：

```java
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin(from -> {
                    from.defaultSuccessUrl("/home");
                })
                .oauth2Login(Customizer.withDefaults())
                .csrf().disable();
        return http.build();
    }
```



<br />

下面我们将配置OAuth2客户端基于MySql数据库的存储方式，你也可以从[Spring Security 持久化OAuth2客户端](https://relive27.github.io/blog/persisrence-oauth2-client) 了解详细信息。

```java
    /**
     * 定义JDBC 客户端注册存储库
     *
     * @param jdbcTemplate
     * @return
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcClientRegistrationRepository(jdbcTemplate);
    }

    /**
     * 负责{@link org.springframework.security.oauth2.client.OAuth2AuthorizedClient}在 Web 请求之间进行持久化
     *
     * @param jdbcTemplate
     * @param clientRegistrationRepository
     * @return
     */
    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            JdbcTemplate jdbcTemplate,
            ClientRegistrationRepository clientRegistrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository);
    }

    /**
     * OAuth2AuthorizedClientRepository 是一个容器类，用于在请求之间保存和持久化授权客户端
     *
     * @param authorizedClientService
     * @return
     */
    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }
```



<br />

我们不在使用基于内存的用户名密码，在初始化数据库时我们已经将用户名密码添加到user表中，所以我们需要实现`UserDetailsService`接口用于Form认证时获取用户信息：

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

这里`UserRepository`继承了`JpaRepository`，提供user表的CRUD，详细代码可以在文末链接中获取。

<br />

现在我们将要解决如何将IdP服务用户角色映射为RP服务已有的角色，在[前面文章](https://relive27.github.io/blog/oauth2-login) 中曾使用`GrantedAuthoritiesMapper`映射角色。在本文中我们将使用`OAuth2UserService`添加角色映射策略，它与`GrantedAuthoritiesMapper`相比更加灵活:

```java
public class OidcRoleMappingUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
    private OidcUserService oidcUserService;
    private final OAuth2ClientRoleRepository oAuth2ClientRoleRepository;

    //...

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = oidcUserService.loadUser(userRequest);

        OidcIdToken idToken = userRequest.getIdToken();
        List<String> role = idToken.getClaimAsStringList("role");
        Set<SimpleGrantedAuthority> mappedAuthorities = role.stream()
                .map(r -> oAuth2ClientRoleRepository.findByClientRegistrationIdAndRoleCode(userRequest.getClientRegistration().getRegistrationId(), r))
                .map(OAuth2ClientRole::getRole).map(Role::getRoleCode).map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

        return oidcUser;
    }
}

```



最后我们将创建`HomeController`，通过控制页面中展示内容使测试效果视觉上更加显著，我们将根据角色展示不同信息，使用[thymeleaf](https://www.thymeleaf.org/) 模版引擎渲染。

```java
@Controller
public class HomeController {

    private static Map<String, List<String>> articles = new HashMap<>();

    static {
        articles.put("ROLE_OPERATION", Arrays.asList("Java"));
        articles.put("ROLE_SYSTEM", Arrays.asList("Java", "Python", "C++"));
    }

    @GetMapping("/home")
    public String home(Authentication authentication, Model model) {
        String authority = authentication.getAuthorities().iterator().next().getAuthority();
        model.addAttribute("articles", articles.get(authority));
        return "home";
    }
}

```



完成配置后，我们可以访问 http://127.0.0.1:8070/home 进行测试。

### 结论

在本文中分享了Spring Security对于OpenID Connect的支持。与往常一样，本文中使用的源代码可[在 GitHub 上](https://github.com/ReLive27/spring-security-oauth2-sample/tree/main/oidc-login) 获得。
