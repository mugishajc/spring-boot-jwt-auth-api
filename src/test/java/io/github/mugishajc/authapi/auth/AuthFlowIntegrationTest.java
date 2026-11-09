package io.github.mugishajc.authapi.auth;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.mugishajc.authapi.support.IntegrationTestBase;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthFlowIntegrationTest extends IntegrationTestBase {

    @Test
    void registerReturnsTokensAndStoresBcryptHash() throws Exception {
        postJson("/api/auth/register", Map.of(
                "email", "Aline@Example.com", "password", PASSWORD, "fullName", "Aline Uwase"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.user.email").value("aline@example.com"))
                .andExpect(jsonPath("$.user.role").value("USER"))
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist());

        String hash = users.findByEmailIgnoreCase("aline@example.com").orElseThrow().getPasswordHash();
        assertThat(hash).startsWith("$2a$").doesNotContain(PASSWORD);
    }

    @Test
    void registeringTheSameEmailTwiceIsAConflict() throws Exception {
        register("eric@example.com");
        postJson("/api/auth/register", Map.of(
                "email", "ERIC@example.com", "password", PASSWORD, "fullName", "Eric"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.title").value("Email already registered"));
    }

    @Test
    void invalidRegistrationReportsEachField() throws Exception {
        postJson("/api/auth/register", Map.of("email", "not-an-email", "password", "short", "fullName", ""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists())
                .andExpect(jsonPath("$.errors.fullName").exists());
    }

    @Test
    void malformedJsonIsABadRequest() throws Exception {
        mvc.perform(post("/api/auth/login")
                        .contentType("application/json").content("{\"email\":"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginWithCorrectPasswordReturnsTokens() throws Exception {
        register("grace@example.com");
        JsonNode auth = login("grace@example.com", PASSWORD);
        assertThat(auth.get("accessToken").asText()).isNotBlank();
    }

    @Test
    void wrongPasswordAndUnknownEmailLookTheSame() throws Exception {
        register("grace@example.com");
        String wrongPassword = postJson("/api/auth/login", Map.of("email", "grace@example.com", "password", "nope-nope"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String unknownEmail = postJson("/api/auth/login", Map.of("email", "nobody@example.com", "password", "nope-nope"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(wrongPassword).get("detail"))
                .isEqualTo(json.readTree(unknownEmail).get("detail"));
    }

    @Test
    void meRequiresAValidAccessToken() throws Exception {
        JsonNode auth = register("patrick@example.com");

        mvc.perform(get("/api/users/me").header("Authorization", bearer(auth)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("patrick@example.com"));

        mvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"))
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void tamperedAccessTokenIsRejected() throws Exception {
        String token = register("patrick@example.com").get("accessToken").asText();
        String[] parts = token.split("\\.");
        // Swap the payload for one claiming to be an admin, keep the old signature.
        String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"sub\":\"1\",\"role\":\"ADMIN\",\"typ\":\"access\",\"iss\":\"jwt-auth-api\"}".getBytes(StandardCharsets.UTF_8));
        String forged = parts[0] + "." + forgedPayload + "." + parts[2];

        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + forged))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer not.a.jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshRotatesTheRefreshToken() throws Exception {
        JsonNode first = register("diane@example.com");
        String oldRefresh = first.get("refreshToken").asText();

        String body = postJson("/api/auth/refresh", Map.of("refreshToken", oldRefresh))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken", not(oldRefresh)))
                .andReturn().getResponse().getContentAsString();
        JsonNode second = json.readTree(body);

        mvc.perform(get("/api/users/me").header("Authorization", bearer(second)))
                .andExpect(status().isOk());
    }

    @Test
    void reusingARotatedRefreshTokenRevokesTheWholeSession() throws Exception {
        JsonNode first = register("diane@example.com");
        String stolen = first.get("refreshToken").asText();

        JsonNode legit = json.readTree(postJson("/api/auth/refresh", Map.of("refreshToken", stolen))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());

        // An attacker replays the old token after the real client has rotated it.
        postJson("/api/auth/refresh", Map.of("refreshToken", stolen))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail", containsString("revoked")));

        // The legitimate client's newer token is now revoked too.
        postJson("/api/auth/refresh", Map.of("refreshToken", legit.get("refreshToken").asText()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutRevokesTheRefreshToken() throws Exception {
        String refresh = register("diane@example.com").get("refreshToken").asText();

        postJson("/api/auth/logout", Map.of("refreshToken", refresh)).andExpect(status().isNoContent());
        postJson("/api/auth/refresh", Map.of("refreshToken", refresh)).andExpect(status().isUnauthorized());
        // Logging out twice is harmless.
        postJson("/api/auth/logout", Map.of("refreshToken", refresh)).andExpect(status().isNoContent());
    }

    @Test
    void unknownRefreshTokenIsUnauthorized() throws Exception {
        postJson("/api/auth/refresh", Map.of("refreshToken", "made-up-token"))
                .andExpect(status().isUnauthorized());
    }
}
