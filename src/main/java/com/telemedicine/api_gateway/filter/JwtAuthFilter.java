package com.telemedicine.api_gateway.filter;

import com.telemedicine.api_gateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Component
@Order(-1)
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    @Autowired
    private JwtUtil jwtUtil;

    public JwtAuthFilter() {
        super(Config.class);  // REQUIRED — this fixes the UnsupportedOperationException
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Collections.singletonList("roles");
    }

    public static class Config {

        private List<String> roles;

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(String roles) {
            this.roles = Arrays.asList(roles.split(","));
        }

    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            if (exchange.getRequest().getMethod().name().equalsIgnoreCase("OPTIONS")) {

                exchange.getResponse().setStatusCode(HttpStatus.OK);
                exchange.getResponse().getHeaders().add("Access-Control-Allow-Origin", "http://localhost:5173");
                exchange.getResponse().getHeaders().add("Access-Control-Allow-Credentials", "true");
                exchange.getResponse().getHeaders().add("Access-Control-Allow-Headers", "*");
                exchange.getResponse().getHeaders().add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");

                return exchange.getResponse().setComplete();
            }

            String path = exchange.getRequest().getPath().toString();

            if (path.startsWith("/auth/login") || path.startsWith("/auth/register")) {
                return chain.filter(exchange); // no JWT required
            }

            String token = extractToken(exchange.getRequest());

            if (token == null || !jwtUtil.validate(token)) {
                return unauthorized(exchange);
            }

            String role = jwtUtil.extractRole(token);
            System.out.println(role);


            List<String> allowedRoles = config.getRoles();
            System.out.println("Allowed Roles: " + allowedRoles);

            if (allowedRoles != null && !allowedRoles.contains(role)) {
                return forbidden(exchange);
            }

            String email = jwtUtil.extractEmail(token);
            System.out.println(email);


            ServerHttpRequest mutatedReq = exchange.getRequest().mutate()
                    .header("X-User-Email", email != null ? email : "")
                    .header("X-User-Role", role != null ? role : "")
                    .build();


            return chain.filter(exchange.mutate().request(mutatedReq).build());
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
