package io.github.mugishajc.authapi.user;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.mugishajc.authapi.support.IntegrationTestBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RoleAccessIntegrationTest extends IntegrationTestBase {

    private User admin;
    private User member;
    private JsonNode adminAuth;
    private JsonNode memberAuth;

    @BeforeEach
    void seedUsers() throws Exception {
        admin = createUser("admin@example.com", Role.ADMIN);
        member = createUser("member@example.com", Role.USER);
        adminAuth = login("admin@example.com", PASSWORD);
        memberAuth = login("member@example.com", PASSWORD);
    }

    @Test
    void anonymousCallerGets401OnAdminEndpoints() throws Exception {
        mvc.perform(get("/api/admin/users")).andExpect(status().isUnauthorized());
    }

    @Test
    void regularUserGets403OnAdminEndpoints() throws Exception {
        mvc.perform(get("/api/admin/users").header("Authorization", bearer(memberAuth)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.title").value("Forbidden"));
        mvc.perform(patch("/api/admin/users/{id}/role", member.getId())
                        .header("Authorization", bearer(memberAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isForbidden());

        assertThat(users.findById(member.getId()).orElseThrow().getRole()).isEqualTo(Role.USER);
    }

    @Test
    void adminCanListUsersWithPaging() throws Exception {
        mvc.perform(get("/api/admin/users").param("size", "1").param("sort", "email,asc")
                        .header("Authorization", bearer(adminAuth)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content[0].email").value("admin@example.com"))
                .andExpect(jsonPath("$.page.totalElements").value(2));
    }

    @Test
    void adminCanFetchSingleUserAndGets404ForUnknownId() throws Exception {
        mvc.perform(get("/api/admin/users/{id}", member.getId()).header("Authorization", bearer(adminAuth)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("member@example.com"));
        mvc.perform(get("/api/admin/users/{id}", 999_999).header("Authorization", bearer(adminAuth)))
                .andExpect(status().isNotFound());
    }

    @Test
    void promotingAUserSignsThemOutSoTheNewRoleTakesEffect() throws Exception {
        mvc.perform(patch("/api/admin/users/{id}/role", member.getId())
                        .header("Authorization", bearer(adminAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));

        postJson("/api/auth/refresh", Map.of("refreshToken", memberAuth.get("refreshToken").asText()))
                .andExpect(status().isUnauthorized());

        JsonNode fresh = login("member@example.com", PASSWORD);
        mvc.perform(get("/api/admin/users").header("Authorization", bearer(fresh)))
                .andExpect(status().isOk());
    }

    @Test
    void adminCannotChangeTheirOwnRole() throws Exception {
        mvc.perform(patch("/api/admin/users/{id}/role", admin.getId())
                        .header("Authorization", bearer(adminAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"USER\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void invalidRoleValueIsABadRequest() throws Exception {
        mvc.perform(patch("/api/admin/users/{id}/role", member.getId())
                        .header("Authorization", bearer(adminAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"SUPERUSER\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void disabledUserCannotLogInOrRefresh() throws Exception {
        mvc.perform(patch("/api/admin/users/{id}/status", member.getId())
                        .header("Authorization", bearer(adminAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));

        postJson("/api/auth/login", Map.of("email", "member@example.com", "password", PASSWORD))
                .andExpect(status().isUnauthorized());
        postJson("/api/auth/refresh", Map.of("refreshToken", memberAuth.get("refreshToken").asText()))
                .andExpect(status().isUnauthorized());
    }
}
