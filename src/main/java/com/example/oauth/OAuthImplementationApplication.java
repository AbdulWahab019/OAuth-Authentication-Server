package com.example.oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@SpringBootApplication
@EnableResourceServer
public class OAuthImplementationApplication {
    public static void main(String[] args) {
        SpringApplication.run(OAuthImplementationApplication.class, args);
    }
}