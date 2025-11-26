package com.telemedicine.api_gateway.filter;

import com.telemedicine.api_gateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    @Autowired
    private JwtUtil jwtUtil;

    public JwtAuthFilter() {
        super(Config.class);  // REQUIRED — this fixes the UnsupportedOperationException
    }

    public static class Config {}

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            String token = extractToken(exchange.getRequest());

            if (token == null || !jwtUtil.validate(token)) {
                return unauthorized(exchange);
            }

            String role = jwtUtil.extractRole(token);

            List<String> allowedRoles = (List<String>) exchange.getAttribute("roles");
            if (allowedRoles != null && !allowedRoles.contains(role)) {
                return forbidden(exchange);
            }

            return chain.filter(exchange);
        };
    }

    private String extractToken(ServerHttpRequest req) {
        String auth = req.getHeaders().getFirst("Authorization");
        if (auth != null && auth.startsWith("Bearer "))
            return auth.substring(7);
        return null;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(
                HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> forbidden(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }
}
