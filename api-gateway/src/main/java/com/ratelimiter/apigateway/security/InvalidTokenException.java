package com.ratelimiter.apigateway.security;

/** The token is not acceptable. The reason is for server logs only and is never sent to the client. */
public class InvalidTokenException extends Exception {

    public InvalidTokenException(String reason) {
        super(reason);
    }

    public InvalidTokenException(String reason, Throwable cause) {
        super(reason, cause);
    }
}
