package com.wclsolution.docpal.api.security.jwt.exception;

import com.wclsolution.docpal.api.security.jwt.JwtToken;
import org.springframework.security.core.AuthenticationException;

/**
 * The type Jwt token verification exception.
 */
public class JwtTokenVerificationException extends AuthenticationException {
    private static final long serialVersionUID = -5959543783324224864L;

    private JwtToken token;

    /**
     * Instantiates a new Jwt token verification exception.
     *
     * @param msg the msg
     */
    public JwtTokenVerificationException(String msg) {
        super(msg);
    }

    /**
     * Instantiates a new Jwt token verification exception.
     *
     * @param token the token
     * @param msg   the msg
     * @param t     the t
     */
    public JwtTokenVerificationException(JwtToken token, String msg, Throwable t) {
        super(msg, t);
        this.token = token;
    }

    /**
     * Token string.
     *
     * @return the string
     */
    public String token() {
        return this.token.getToken();
    }
}
