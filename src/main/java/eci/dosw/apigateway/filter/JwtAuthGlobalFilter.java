package eci.dosw.apigateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Mono;

/**
 * Único punto de confianza para X-User-Id en todo el sistema.
 *
 * <p>Todos los servicios (chat-service, Parches-Service, etc.) autorizan
 * confiando en el header {@code X-User-Id} sin validar nada más — pero ese
 * header lo mandaba el CLIENTE (decodificando su propio JWT), así que
 * cualquiera podía mandar el X-User-Id que quisiera y suplantar a otro
 * usuario. Acá se valida la firma del JWT (mismo secreto/algoritmo HMAC que
 * usa identity-service, ver JwtService) y se sobreescribe X-User-Id con el
 * {@code sub} del token ya verificado — el valor que venga del cliente en
 * ese header se descarta siempre, sea cual sea.
 *
 * <p>Rutas públicas (login, registro, refresh, etc.): se dejan pasar sin
 * token. Todo lo demás exige Authorization: Bearer válido o corta con 401
 * antes de llegar al servicio.
 */
@Component
public class JwtAuthGlobalFilter implements GlobalFilter, Ordered {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    private static final Set<String> PUBLIC_PREFIXES = Set.of(
            "/api/v1/auth/init-verification",
            "/api/v1/auth/complete-registration",
            "/api/v1/auth/verify-otp",
            "/api/v1/auth/resend-otp",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password",
            "/docs/",
            "/actuator/",
            // WebSocket (STOMP): el handshake HTTP de upgrade no lleva
            // Authorization (stomp_dart_client no lo manda ahí). La
            // identidad se sigue validando dentro de cada servicio a
            // partir del header X-User-Id que manda el cliente en el
            // frame STOMP CONNECT/SEND — ese riesgo de suplantación queda
            // sin resolver acá, es un gap conocido y pendiente aparte.
            "/ws-chat/",
            "/ws-location/"
    );

    private SecretKey signingKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    private boolean isPublic(String path) {
        return PUBLIC_PREFIXES.stream().anyMatch(path::startsWith);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (isPublic(path)) {
            return chain.filter(stripClientUserId(exchange));
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange, "Falta el token de autenticación.");
        }

        String userId;
        try {
            userId = Jwts.parser()
                    .verifyWith(signingKey())
                    .build()
                    .parseSignedClaims(authHeader.substring(7))
                    .getPayload()
                    .getSubject();
        } catch (Exception e) {
            return unauthorized(exchange, "Token inválido o expirado.");
        }

        if (userId == null || userId.isBlank()) {
            return unauthorized(exchange, "Token inválido o expirado.");
        }

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove("X-User-Id");
                    headers.add("X-User-Id", userId);
                })
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    /** Rutas públicas no llevan identidad: igual se descarta cualquier
     *  X-User-Id que venga del cliente para que ningún handler downstream
     *  confíe en él por accidente. */
    private ServerWebExchange stripClientUserId(ServerWebExchange exchange) {
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(headers -> headers.remove("X-User-Id"))
                .build();
        return exchange.mutate().request(mutatedRequest).build();
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        byte[] body = ("{\"error\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
    }

    /** Antes de que Spring Cloud Gateway rutee la petición. */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
