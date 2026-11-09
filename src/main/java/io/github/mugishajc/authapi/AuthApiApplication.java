package io.github.mugishajc.authapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

// Users authenticate through AuthService and JWTs, so the default in-memory
// user with a generated password is not wanted.
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class AuthApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthApiApplication.class, args);
    }
}
