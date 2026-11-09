package io.github.mugishajc.authapi.security;

import io.github.mugishajc.authapi.user.Role;

/** The identity carried inside a verified access token. */
public record AccessTokenClaims(Long userId, String email, Role role) {
}
