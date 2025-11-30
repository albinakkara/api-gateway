package com.telemedicine.api_gateway.filter;

import com.telemedicine.api_gateway.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private ServerWebExchange exchange;

    @Mock
    private ServerHttpRequest request;

    @Mock
    private ServerHttpResponse response;

    @Mock
    private GatewayFilterChain chain;

    @InjectMocks
    private JwtAuthFilter jwtAuthFilter;

    @Test
    void optionsRequest_isShortCircuitedWithOk() {
        JwtAuthFilter.Config config = new JwtAuthFilter.Config();
        GatewayFilter filter = jwtAuthFilter.apply(config);

        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.OPTIONS);
        when(exchange.getResponse()).thenReturn(response);
        when(response.getHeaders()).thenReturn(new HttpHeaders());
        when(response.setComplete()).thenReturn(Mono.empty());

        Mono<Void> result = filter.filter(exchange, chain);

        verify(response).setStatusCode(HttpStatus.OK);
        verify(chain, never()).filter(any(ServerWebExchange.class));
        assertNotNull(result);
    }

    @Test
    void publicLoginPath_skipsJwtValidation() {
        JwtAuthFilter.Config config = new JwtAuthFilter.Config();
        GatewayFilter filter = jwtAuthFilter.apply(config);

        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.POST);

        RequestPath path = mock(RequestPath.class);
        when(request.getPath()).thenReturn(path);
        when(path.toString()).thenReturn("/auth/login");

        when(chain.filter(exchange)).thenReturn(Mono.empty());

        Mono<Void> result = filter.filter(exchange, chain);

        verify(chain, times(1)).filter(exchange);
        verify(jwtUtil, never()).validate(anyString());
        assertNotNull(result);
    }

    @Test
    void missingOrInvalidToken_returnsUnauthorized() {
        JwtAuthFilter.Config config = new JwtAuthFilter.Config();
        GatewayFilter filter = jwtAuthFilter.apply(config);

        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.GET);

        RequestPath path = mock(RequestPath.class);
        when(request.getPath()).thenReturn(path);
        when(path.toString()).thenReturn("/secure/path");

        HttpHeaders headers = new HttpHeaders(); // no Authorization header
        when(request.getHeaders()).thenReturn(headers);

        when(exchange.getResponse()).thenReturn(response);
        when(response.setComplete()).thenReturn(Mono.empty());

        Mono<Void> result = filter.filter(exchange, chain);

        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any(ServerWebExchange.class));
        assertNotNull(result);
    }
}
