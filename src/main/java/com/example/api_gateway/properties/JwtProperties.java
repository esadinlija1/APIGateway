package com.example.api_gateway.properties;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix="jwt")
public class JwtProperties {
    private String secret;

    public String getSecret() {
        return secret;
    }
    @PostConstruct
    public void checkSecret() {
        System.out.println("🔹 Učitana vrijednost jwtSecret: " + secret);
    }

    @PostConstruct
    public void checkSecretInit() {
        System.out.println("🔹 Vrijednost u JwtProperties nakon inicijalizacije: " + secret);
    }


    public void setSecret(String secret) {
        this.secret = secret;
    }
}
