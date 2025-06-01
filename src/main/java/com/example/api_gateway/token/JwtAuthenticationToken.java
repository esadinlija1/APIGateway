package com.example.api_gateway.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private final String token;

    public JwtAuthenticationToken(String token,Boolean isAuthenticated) {
        super(null);
        this.token = token;
        setAuthenticated(isAuthenticated);
        System.out.println("Autentifikovan korisnik kroz JWT token!");
    }

    @Override
    public Object getCredentials() {
        return token; // JWT token kao kredencijal
    }

    @Override
    public Object getPrincipal() {
        return token; // Token može biti principal ili ga možeš kasnije dekodirati
    }
}

