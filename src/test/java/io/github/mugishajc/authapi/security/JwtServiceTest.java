package io.github.mugishajc.authapi.security;

import io.github.mugishajc.authapi.user.Role;
import io.github.mugishajc.authapi.user.User;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String SECRET = "unit-test-secret-with-at-least-32-bytes";
    private static final Instant NOW = Instant.parse("2026-11-09T08:00:00Z");

    private final JwtProperties properties =
            new JwtProperties(SECRET, "jwt-auth-api", Duration.ofMinutes(15), Duration.ofDays(7));

    @Test
    void issuedTokenVerifiesAndCarriesIdentity() {
        JwtService service = serviceAt(NOW);
        JwtService.IssuedToken token = service.issueAccessToken(user(7L, Role.ADMIN));

        assertThat(token.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(service.verifyAccessToken(token.value()))
                .contains(new AccessTokenClaims(7L, "user7@example.com", Role.ADMIN));
    }

    @Test
    void expiredTokenIsRejected() {
        String token = serviceAt(NOW).issueAccessToken(user(1L, Role.USER)).value();
        JwtService later = serviceAt(NOW.plus(Duration.ofMinutes(16)));
        assertThat(later.verifyAccessToken(token)).isEmpty();
    }

    @Test
    void tokenSignedWithAnotherSecretIsRejected() {
        JwtProperties other = new JwtProperties("a-completely-different-secret-value-123", "jwt-auth-api",
                Duration.ofMinutes(15), Duration.ofDays(7));
        String token = new JwtService(other, fixed(NOW)).issueAccessToken(user(1L, Role.USER)).value();
        assertThat(serviceAt(NOW).verifyAccessToken(token)).isEmpty();
    }

    @Test
    void tokenFromAnotherIssuerIsRejected() {
        JwtProperties other = new JwtProperties(SECRET, "some-other-service", Duration.ofMinutes(15), Duration.ofDays(7));
        String token = new JwtService(other, fixed(NOW)).issueAccessToken(user(1L, Role.USER)).value();
        assertThat(serviceAt(NOW).verifyAccessToken(token)).isEmpty();
    }

    @Test
    void unsignedTokenIsRejected() {
        // alg=none with a valid-looking payload must never be accepted.
        String header = b64("{\"alg\":\"none\"}");
        String payload = b64("{\"sub\":\"1\",\"iss\":\"jwt-auth-api\",\"role\":\"ADMIN\",\"typ\":\"access\"}");
        assertThat(serviceAt(NOW).verifyAccessToken(header + "." + payload + ".")).isEmpty();
    }

    @Test
    void blankAndGarbageInputIsRejected() {
        JwtService service = serviceAt(NOW);
        assertThat(service.verifyAccessToken(null)).isEmpty();
        assertThat(service.verifyAccessToken("")).isEmpty();
        assertThat(service.verifyAccessToken("abc.def.ghi")).isEmpty();
    }

    @Test
    void refusesToStartWithMissingOrShortSecret() {
        assertThatThrownBy(() -> new JwtService(
                new JwtProperties("", "x", Duration.ofMinutes(1), Duration.ofDays(1)), fixed(NOW)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JWT_SECRET");
        assertThatThrownBy(() -> new JwtService(
                new JwtProperties("too-short", "x", Duration.ofMinutes(1), Duration.ofDays(1)), fixed(NOW)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    private JwtService serviceAt(Instant instant) {
        return new JwtService(properties, fixed(instant));
    }

    private static Clock fixed(Instant instant) {
        return Clock.fixed(instant, ZoneOffset.UTC);
    }

    private static User user(Long id, Role role) {
        User user = new User("user" + id + "@example.com", "hash", "User " + id, role);
        ReflectionTestUtils.setField(user, "id", id);
        return user;
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
}
