package com.wclsolution.docpal.api.security.jwt.exception;

import com.wclsolution.docpal.api.security.jwt.JwtToken;
import org.springframework.security.core.AuthenticationException;

/**
 * The type Jwt token other exception.
 */
public class JwtTokenOtherException extends AuthenticationException {

    private static final long serialVersionUID = -5959543783324222264L;

    private JwtToken token;

    /**
     * Instantiates a new Jwt token other exception.
     *
     * @param msg the msg
     */
    public JwtTokenOtherException(String msg) {
        super(msg);
    }

    /**
     * Instantiates a new Jwt token other exception.
     *
     * @param token the token
     * @param msg   the msg
     * @param t     the t
     */
    public JwtTokenOtherException(JwtToken token, String msg, Throwable t) {
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
