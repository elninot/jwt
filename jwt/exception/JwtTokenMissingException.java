package com.wclsolution.docpal.api.security.jwt.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * The type Jwt token missing exception.
 */
public class JwtTokenMissingException extends AuthenticationException {
    /**
     * Instantiates a new Jwt token missing exception.
     *
     * @param msg the msg
     */
    public JwtTokenMissingException(String msg) {
        super(msg);
    }
}
