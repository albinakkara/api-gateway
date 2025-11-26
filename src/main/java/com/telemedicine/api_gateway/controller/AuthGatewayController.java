package com.telemedicine.api_gateway.controller;

import com.telemedicine.api_gateway.dto.UserResponseDto;
import com.telemedicine.api_gateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Locale;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthGatewayController {

    @Autowired
    private WebClient.Builder webClient;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public Mono<Map<String, String>> login(@RequestBody Map<String, String> loginRequest) {

        return webClient.build()
                .post()
                .uri("http://user-service/auth/login") // Eureka or static URL
                .bodyValue(loginRequest)
                .retrieve()
                .bodyToMono(UserResponseDto.class)
                .map(user -> {
                    String token = jwtUtil.generateToken(user.getEmail(), user.getRole().toUpperCase(Locale.ROOT));
                    return Map.of("token", token);
                });
    }
}

