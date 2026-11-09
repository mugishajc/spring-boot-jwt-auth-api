package io.github.mugishajc.authapi.config;

import io.github.mugishajc.authapi.user.Role;
import io.github.mugishajc.authapi.user.User;
import io.github.mugishajc.authapi.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Locale;

/**
 * Creates the first admin account on startup when ADMIN_EMAIL and
 * ADMIN_PASSWORD are provided. Does nothing if the account already exists, so
 * it is safe to leave configured.
 */
@Component
public class AdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final String email;
    private final String password;

    public AdminBootstrap(UserRepository users, PasswordEncoder passwordEncoder,
                          @Value("${app.bootstrap-admin.email:}") String email,
                          @Value("${app.bootstrap-admin.password:}") String password) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.email = email;
        this.password = password;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!StringUtils.hasText(email) || !StringUtils.hasText(password)) {
            return;
        }
        String normalised = email.strip().toLowerCase(Locale.ROOT);
        if (users.existsByEmailIgnoreCase(normalised)) {
            return;
        }
        users.save(new User(normalised, passwordEncoder.encode(password), "Administrator", Role.ADMIN));
        log.info("Created bootstrap admin account {}", normalised);
    }
}
