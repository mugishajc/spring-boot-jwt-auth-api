package io.github.mugishajc.authapi.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * JWT settings. The secret has no default in the base configuration on purpose:
 * outside the dev profile the app refuses to start until JWT_SECRET is set.
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        String secret,
        String issuer,
        Duration accessTokenTtl,
        Duration refreshTokenTtl) {
}
