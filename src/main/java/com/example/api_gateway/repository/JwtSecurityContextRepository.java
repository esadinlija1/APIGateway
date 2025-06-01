package com.example.api_gateway.repository;

import com.example.api_gateway.properties.JwtProperties;
import com.example.api_gateway.token.JwtAuthenticationToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.netty.buffer.ByteBuf;
import jakarta.annotation.PostConstruct;
import org.hibernate.validator.internal.util.stereotypes.Lazy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;

@Component
public class JwtSecurityContextRepository implements ServerSecurityContextRepository {

    @Autowired
    @Lazy
    private JwtProperties jwtProperties;

    @PostConstruct
    public void checkRepositoryInit() {
        System.out.println("🔹 JwtSecurityContextRepository inicijalizovan! " + jwtProperties);
    }



    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        System.out.println("Učitana vrijednost jwtSecret: " + jwtProperties.getSecret());

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.replace("Bearer ", "");

            try {
                Claims claims = Jwts.parser()
                        .setSigningKey(jwtProperties.getSecret().getBytes())
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                boolean isAuthenticated = claims != null;
                Authentication authentication = new JwtAuthenticationToken(token, isAuthenticated);
                SecurityContext context = new SecurityContextImpl(authentication);

                System.out.println("Kreiran SecurityContext sa validnim JWT!");

                return Mono.just(context);

            } catch (Exception e) {
                System.out.println("JWT parsing failed: " + e.getMessage());
                return Mono.empty();
            }
        }

        System.out.println("SecurityContext nije kreiran - nema validnog tokena!");
        return Mono.empty();
    }


    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.empty();
    }
}


