package io.github.mugishajc.authapi.auth;

import io.github.mugishajc.authapi.auth.dto.AuthResponse;
import io.github.mugishajc.authapi.auth.dto.LoginRequest;
import io.github.mugishajc.authapi.auth.dto.RegisterRequest;
import io.github.mugishajc.authapi.common.EmailAlreadyUsedException;
import io.github.mugishajc.authapi.security.JwtService;
import io.github.mugishajc.authapi.user.Role;
import io.github.mugishajc.authapi.user.User;
import io.github.mugishajc.authapi.user.UserRepository;
import io.github.mugishajc.authapi.user.dto.UserResponse;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Service
public class AuthService {

    private static final String BAD_CREDENTIALS = "Invalid email or password";

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokens;

    // Used to burn the same BCrypt time for unknown emails as for wrong passwords,
    // so response timing does not reveal which emails are registered.
    private final String dummyHash;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder,
                       JwtService jwtService, RefreshTokenService refreshTokens) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokens = refreshTokens;
        this.dummyHash = passwordEncoder.encode("timing-equaliser");
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        String email = normaliseEmail(request.email());
        if (users.existsByEmailIgnoreCase(email)) {
            throw new EmailAlreadyUsedException();
        }
        User user = new User(email, passwordEncoder.encode(request.password()), request.fullName().strip(), Role.USER);
        try {
            user = users.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            // Lost a race with a concurrent registration for the same email.
            throw new EmailAlreadyUsedException();
        }
        return tokensFor(user, refreshTokens.issue(user));
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = users.findByEmailIgnoreCase(normaliseEmail(request.email())).orElse(null);
        if (user == null) {
            passwordEncoder.matches(request.password(), dummyHash);
            throw new BadCredentialsException(BAD_CREDENTIALS);
        }
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new BadCredentialsException(BAD_CREDENTIALS);
        }
        if (!user.isEnabled()) {
            throw new DisabledException("Account is disabled");
        }
        return tokensFor(user, refreshTokens.issue(user));
    }

    @Transactional(noRollbackFor = RuntimeException.class)
    public AuthResponse refresh(String refreshToken) {
        RefreshTokenService.Rotation rotation = refreshTokens.rotate(refreshToken);
        return tokensFor(rotation.user(), rotation.refreshToken());
    }

    @Transactional
    public void logout(String refreshToken) {
        refreshTokens.revoke(refreshToken);
    }

    private AuthResponse tokensFor(User user, String refreshToken) {
        JwtService.IssuedToken access = jwtService.issueAccessToken(user);
        return AuthResponse.bearer(access.value(), refreshToken, jwtService.accessTokenTtlSeconds(),
                UserResponse.from(user));
    }

    static String normaliseEmail(String email) {
        return email.strip().toLowerCase(Locale.ROOT);
    }
}
