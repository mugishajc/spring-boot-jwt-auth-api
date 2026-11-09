package io.github.mugishajc.authapi.user;

public enum Role {
    USER,
    ADMIN;

    /** Spring Security expects role authorities to carry the ROLE_ prefix. */
    public String authority() {
        return "ROLE_" + name();
    }
}
