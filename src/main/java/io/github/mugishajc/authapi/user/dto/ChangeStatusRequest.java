package io.github.mugishajc.authapi.user.dto;

import jakarta.validation.constraints.NotNull;

public record ChangeStatusRequest(@NotNull Boolean enabled) {
}
