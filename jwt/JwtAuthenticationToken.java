package com.wclsolution.docpal.api.security.jwt;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * The type Jwt authentication token.
 */
public class JwtAuthenticationToken extends UsernamePasswordAuthenticationToken {
    private final String token;

    /**
     * Instantiates a new Jwt authentication token.
     *
     * @param token the token
     */
    public JwtAuthenticationToken(String token) {
        super(null, null);
        this.token = token;
    }

    /**
     * Gets token.
     *
     * @return the token
     */
    public String getToken() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

}
