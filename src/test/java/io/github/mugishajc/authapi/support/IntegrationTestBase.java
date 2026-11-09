package io.github.mugishajc.authapi.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.mugishajc.authapi.auth.RefreshTokenRepository;
import io.github.mugishajc.authapi.user.Role;
import io.github.mugishajc.authapi.user.User;
import io.github.mugishajc.authapi.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public abstract class IntegrationTestBase {

    protected static final String PASSWORD = "Str0ngPassw0rd";

    @Autowired
    protected MockMvc mvc;

    @Autowired
    protected ObjectMapper json;

    @Autowired
    protected UserRepository users;

    @Autowired
    protected RefreshTokenRepository refreshTokens;

    @Autowired
    protected PasswordEncoder passwordEncoder;

    @BeforeEach
    void cleanDatabase() {
        refreshTokens.deleteAll();
        users.deleteAll();
    }

    protected ResultActions postJson(String url, Object body) throws Exception {
        return mvc.perform(post(url)
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(body)));
    }

    protected JsonNode register(String email) throws Exception {
        String body = postJson("/api/auth/register", Map.of(
                "email", email, "password", PASSWORD, "fullName", "Test User"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body);
    }

    protected JsonNode login(String email, String password) throws Exception {
        String body = postJson("/api/auth/login", Map.of("email", email, "password", password))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body);
    }

    protected User createUser(String email, Role role) {
        return users.save(new User(email, passwordEncoder.encode(PASSWORD), "Seeded " + role, role));
    }

    protected static String bearer(JsonNode authResponse) {
        return "Bearer " + authResponse.get("accessToken").asText();
    }
}
