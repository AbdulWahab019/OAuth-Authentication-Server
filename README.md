# OAuth 2.0 - Authentication Server using Spring Security

## 1) Create Spring Boot application

## 2) Add Following Dependency:

```
    <dependency>
        <groupId>org.springframework.security.oauth</groupId>            
        <artifactId>spring-security-oauth2</artifactId>
        <version>2.4.1.RELEASE</version>
    </dependency>
```

## 3) Add following in Application.properties file:
```
    server.port=8081
    server.servlet.context-path=/auth
    user.oauth.clientId=R2dpxQ3vPrtfgF72
    user.oauth.clientSecret=fDw7Mpkk5czHNuSRtmhGmAGL42CaxQB9
    user.oauth.redirectUris=http://localhost:8080/login/oauth2/code/
    user.oauth.user.username=[username]
    user.oauth.user.password=[password]
```

## 4) Add (@EnableResourceServer) Annotation before Main class name.

## 5) Create a new Class for Authentication server Configuration named as AuthServerConfig.java. This class will create and return our JSON Web Tokens when the client authenticates properly.

```
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.security.crypto.password.PasswordEncoder;
    import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
    import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
    import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
    import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

    @Configuration
    @EnableAuthorizationServer
    public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

        private final PasswordEncoder passwordEncoder;
        @Value("${user.oauth.clientId}")
        private String ClientID;
        @Value("${user.oauth.clientSecret}")
        private String ClientSecret;
        @Value("${user.oauth.redirectUris}")
        private String RedirectURLs;

        public AuthServerConfig(PasswordEncoder passwordEncoder) {
            this.passwordEncoder = passwordEncoder;
        }

        @Override
        public void configure(
            AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
            oauthServer.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                .withClient(ClientID)
                .secret(passwordEncoder.encode(ClientSecret))
                .authorizedGrantTypes("authorization_code")
                .scopes("user_info")
                .autoApprove(true)
                .redirectUris(RedirectURLs);
        }
    }
```

## 6) Create a SecurityConfiguration class, that actually authenticates requests to authorization server.

```
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.core.annotation.Order;
    import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

    @Configuration
    @Order(1)
    public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        @Value("${user.oauth.user.username}")
        private String username;
        @Value("${user.oauth.user.password}")
        private String password;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.requestMatchers()
                .antMatchers("/login", "/oauth/authorize")
                .and()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication()
                .withUser(username)
                .password(passwordEncoder().encode(password))
                .roles("USER");
        }

        @Bean
        public BCryptPasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }
```

## 7) Now, create a UserController Class.

```
    import org.springframework.web.bind.annotation.GetMapping;
    import org.springframework.web.bind.annotation.RestController;

    import java.security.Principal;

    @RestController
    public class UserController {

        @GetMapping("/user/me")
        public Principal user(Principal principal) {
            return principal;
        }
    }
```

## 8) Create a new Project for Client Application.

## 9) Add following Dependencies. (Gradle)
```
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
	implementation 'org.springframework.boot:spring-boot-starter-thymeleaf'
	implementation 'org.springframework.boot:spring-boot-starter-web'
	implementation 'org.thymeleaf.extras:thymeleaf-extras-springsecurity5:3.0.4.RELEASE'
```

## 10) Rename Application.properties to Application.yml, and Add following code in it.

```
    server:
      port: 8080
      servlet:
        session:
          cookie:
            name: UISESSION

    spring:
      thymeleaf:
        cache: false
      security:
        oauth2:
          client:
            registration:
              custom-client:
                client-id: R2dpxQ3vPrtfgF72
                client-secret: fDw7Mpkk5czHNuSRtmhGmAGL42CaxQB9
                client-name: Auth Server
                scope: user_info
                provider: custom-provider
                redirect-uri: http://localhost:8080/login/oauth2/code/
                client-authentication-method: basic
                authorization-grant-type: authorization_code
            provider:
              custom-provider:
                token-uri: http://localhost:8081/auth/oauth/token
                authorization-uri: http://localhost:8081/auth/oauth/authorize
                user-info-uri: http://localhost:8081/auth/user/me
                user-name-attribute: name
```

## 11) Create a new controller class WebController, and add Following Code.

```
    @Controller
    public class WebController {

        @RequestMapping("/securedPage")
        public String securedPage(Model model, Principal principal) {
            return "securedPage";
        }

        @RequestMapping("/")
        public String index(Model model, Principal principal) {
            return "index";
        }
    }
```

## 12) Create another Java class named SecurityConfiguration. This class defines the Spring Security configuration for your application: allowing all requests on the home path and requiring authentication for all other routes. it also sets up the Spring Boot OAuth login flow.

```
    @Configuration
    public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/**").authorizeRequests()
                .antMatchers("/", "/login**").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login();
        }
    }
```

## 13) Now, create two template files(index.html, securedPage.html)


    index.html:
```
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Home Page</title>
        </head>
        <body>
            <h1>Spring Security - OAuth Demo</h1>
            <a href="securedPage">Login</a>
        </body>
        </html>
```

    securedPage.html:

```
        <!DOCTYPE html>
        <html xmlns:th="http://www.thymeleaf.org">
        <head>
            <meta charset="UTF-8">
            <title>Secured Page</title>
        </head>
        <body>
        <h1>Secured Page</h1>
        <span th:text="${#authentication.name}"></span>
        </body>
        </html>
```

## 14) Run the Application.