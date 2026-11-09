package io.github.mugishajc.authapi.auth;

import io.github.mugishajc.authapi.common.InvalidTokenException;
import io.github.mugishajc.authapi.security.JwtProperties;
import io.github.mugishajc.authapi.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Opaque, single-use refresh tokens with rotation.
 *
 * <p>Every successful refresh revokes the presented token and issues a new
 * one. If a token that was already rotated shows up again, someone else is
 * holding a copy of it, so every active session of that user is revoked.
 */
@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenRepository repository;
    private final JwtProperties properties;
    private final Clock clock;

    public RefreshTokenService(RefreshTokenRepository repository, JwtProperties properties, Clock clock) {
        this.repository = repository;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public String issue(User user) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Instant now = clock.instant();
        repository.save(new RefreshToken(hash(raw), user, now, now.plus(properties.refreshTokenTtl())));
        return raw;
    }

    /** Validates and consumes {@code raw}, returning the owner and a replacement token. */
    @Transactional(noRollbackFor = InvalidTokenException.class)
    public Rotation rotate(String raw) {
        RefreshToken current = repository.findByTokenHash(hash(raw))
                .orElseThrow(() -> new InvalidTokenException("Refresh token is not recognised"));
        Instant now = clock.instant();
        User user = current.getUser();

        if (current.isRevoked()) {
            int revoked = repository.revokeAllForUser(user.getId(), now);
            log.warn("Reuse of revoked refresh token for user {}; revoked {} active session(s)", user.getId(), revoked);
            throw new InvalidTokenException("Refresh token has been revoked");
        }
        if (current.isExpired(now)) {
            current.revoke(now);
            throw new InvalidTokenException("Refresh token has expired");
        }
        if (!user.isEnabled()) {
            current.revoke(now);
            throw new InvalidTokenException("Account is disabled");
        }

        current.revoke(now);
        return new Rotation(user, issue(user));
    }

    /** Logout. Unknown or already revoked tokens are ignored so logout is idempotent. */
    @Transactional
    public void revoke(String raw) {
        repository.findByTokenHash(hash(raw)).ifPresent(token -> token.revoke(clock.instant()));
    }

    @Transactional
    public void revokeAll(User user) {
        repository.revokeAllForUser(user.getId(), clock.instant());
    }

    static String hash(String raw) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public record Rotation(User user, String refreshToken) {
    }
}
