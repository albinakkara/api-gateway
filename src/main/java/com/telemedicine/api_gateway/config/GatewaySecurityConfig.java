package com.telemedicine.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)  // 🔥 disable CSRF
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/auth/**").permitAll()    // allow register/login
                        .anyExchange().permitAll()              // allow everything else
                );

        return http.build();
    }
}
