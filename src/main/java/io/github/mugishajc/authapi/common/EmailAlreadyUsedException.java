package io.github.mugishajc.authapi.common;

public class EmailAlreadyUsedException extends RuntimeException {

    public EmailAlreadyUsedException() {
        super("An account with this email already exists");
    }
}
