package com.wclsolution.docpal.api.security.authentication.common;

import org.springframework.security.authentication.AuthenticationServiceException;

/**
 * The type Auth method not supported exception.
 */
public class AuthMethodNotSupportedException extends AuthenticationServiceException {
    private static final long serialVersionUID = 3705043083010304496L;

    /**
     * Instantiates a new Auth method not supported exception.
     *
     * @param msg the msg
     */
    public AuthMethodNotSupportedException(String msg) {
        super(msg);
    }
}
