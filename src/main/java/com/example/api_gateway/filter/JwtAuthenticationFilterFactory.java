package com.example.api_gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationFilterFactory extends AbstractGatewayFilterFactory<JwtAuthenticationFilterFactory.Config> {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private static final String AUTH_HEADER = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";

    public JwtAuthenticationFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        System.out.println("JwtAuthenticationFilterFactory filter se izvršava!");

        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst(AUTH_HEADER);
            String path = exchange.getRequest().getPath().toString();

            System.out.println("JwtAuthenticationFilterFactory pozvan za path: " + path);

            // 1. Rute koje ne zahtijevaju autentifikaciju
            if (path.startsWith("/jwt-auth/auth/login") || path.startsWith("/jwt-auth/auth/register")) {
                return chain.filter(exchange);
            }

            if (authHeader == null || !authHeader.startsWith(TOKEN_PREFIX)) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String token = authHeader.replace(TOKEN_PREFIX, "");

            System.out.println("Path: " + path);
            System.out.println("Auth header: " + authHeader);

            try {
                Claims claims = Jwts.parser()
                        .setSigningKey(jwtSecret.getBytes())
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                System.out.println("JWT validiran: " + claims);

                String userId = claims.getSubject(); // "sub" claim
                String email = claims.get("email", String.class);
                String role = claims.get("role", String.class);

                // Dodavanje Authorization zaglavlja i korisničkih podataka
                exchange = exchange.mutate().request(
                        exchange.getRequest().mutate()
                                .header("Authorization", TOKEN_PREFIX + token) // Prosljeđuje token downstream servisima
                                .header("X-User-Id", userId)
                                .header("X-User-Email", email)
                                .header("X-User-Role", role)
                                .build()
                ).build();

                exchange.getRequest().getHeaders().forEach((key, value) -> System.out.println(key + ": " + value));


            } catch (Exception e) {
                System.out.println("JWT parsing failed: " + e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            return chain.filter(exchange);
        };
    }

    public static class Config {
        // Možeš dodati konfiguracione opcije ako su potrebne
    }
}
