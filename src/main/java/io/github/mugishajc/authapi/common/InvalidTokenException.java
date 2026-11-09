package io.github.mugishajc.authapi.common;

/** A refresh or access token was missing, unknown, expired or revoked. */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }
}
