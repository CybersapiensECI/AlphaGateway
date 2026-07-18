package eci.dosw.apigateway.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Mono;

class JwtAuthGlobalFilterTest {

    private static final String SECRET = "unit-test-secret-key-at-least-32-bytes-long!!";

    private static SecretKey key() {
        return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    private static String tokenFor(String userId) {
        return Jwts.builder()
                .subject(userId)
                .issuer("identity-service")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900_000))
                .signWith(key())
                .compact();
    }

    private JwtAuthGlobalFilter newFilter() throws Exception {
        JwtAuthGlobalFilter filter = new JwtAuthGlobalFilter();
        var field = JwtAuthGlobalFilter.class.getDeclaredField("jwtSecret");
        field.setAccessible(true);
        field.set(filter, SECRET);
        return filter;
    }

    /** Captura el exchange (mutado o no) con el que la chain fue invocada. */
    private static final class CapturingChain implements org.springframework.cloud.gateway.filter.GatewayFilterChain {
        ServerWebExchange seen;

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            this.seen = exchange;
            return Mono.empty();
        }
    }

    @Test
    void validToken_overridesXUserIdWithTokenSubject_ignoringClientHeader() throws Exception {
        String realUserId = "11111111-1111-1111-1111-111111111111";
        String forgedUserId = "99999999-9999-9999-9999-999999999999";

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/v1/users/me")
                .header("Authorization", "Bearer " + tokenFor(realUserId))
                .header("X-User-Id", forgedUserId)
                .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        newFilter().filter(exchange, chain).block();

        assertEquals(realUserId, chain.seen.getRequest().getHeaders().getFirst("X-User-Id"));
    }

    @Test
    void missingToken_onProtectedRoute_returns401AndDoesNotCallChain() throws Exception {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/v1/users/me").build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        newFilter().filter(exchange, chain).block();

        assertNull(chain.seen);
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void invalidSignature_returns401() throws Exception {
        SecretKey otherKey = Keys.hmacShaKeyFor(
                "a-completely-different-secret-key-not-the-real-one!!".getBytes(StandardCharsets.UTF_8));
        String forgedToken = Jwts.builder()
                .subject("11111111-1111-1111-1111-111111111111")
                .expiration(new Date(System.currentTimeMillis() + 900_000))
                .signWith(otherKey)
                .compact();

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/v1/users/me")
                .header("Authorization", "Bearer " + forgedToken)
                .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        newFilter().filter(exchange, chain).block();

        assertNull(chain.seen);
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void publicRoute_letsRequestThroughWithoutToken() throws Exception {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/v1/auth/login").build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        newFilter().filter(exchange, chain).block();

        assertEquals("/api/v1/auth/login", chain.seen.getRequest().getURI().getPath());
    }

    @Test
    void publicRoute_stripsClientSuppliedXUserId() throws Exception {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/v1/auth/login")
                .header("X-User-Id", "99999999-9999-9999-9999-999999999999")
                .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        newFilter().filter(exchange, chain).block();

        assertNull(chain.seen.getRequest().getHeaders().getFirst("X-User-Id"));
    }
}
