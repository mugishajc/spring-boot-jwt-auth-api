package io.github.mugishajc.authapi.user.dto;

import io.github.mugishajc.authapi.user.Role;
import jakarta.validation.constraints.NotNull;

public record ChangeRoleRequest(@NotNull Role role) {
}
