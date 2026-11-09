package io.github.mugishajc.authapi.user.dto;

import io.github.mugishajc.authapi.user.Role;
import io.github.mugishajc.authapi.user.User;

import java.time.Instant;

public record UserResponse(Long id, String email, String fullName, Role role, boolean enabled, Instant createdAt) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getFullName(), user.getRole(),
                user.isEnabled(), user.getCreatedAt());
    }
}
