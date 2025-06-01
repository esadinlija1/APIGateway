package com.example.api_gateway.configuration;

import com.example.api_gateway.repository.JwtSecurityContextRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,JwtSecurityContextRepository jwtSecurityContextRepository) {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(exchange -> exchange
                        .pathMatchers( "/jwt-auth/auth/login","/jwt-auth/auth/register").permitAll()
                        .anyExchange().authenticated()
                )
                .securityContextRepository(jwtSecurityContextRepository)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable);

        return http.build();

        /*http.csrf(ServerHttpSecurity.CsrfSpec::disable) // Onemogući CSRF
                .authorizeExchange(exchange -> exchange.anyExchange().permitAll()) // Privremeno dozvoli sve
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable) // Onemogući Basic Auth
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable); // Onemogući Form Login

        return http.build();*/

    }

}
