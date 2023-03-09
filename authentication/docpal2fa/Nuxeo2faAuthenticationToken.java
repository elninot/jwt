package com.wclsolution.docpal.api.security.authentication.docpal2fa;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class Nuxeo2faAuthenticationToken extends UsernamePasswordAuthenticationToken {
    private final String token;

    /**
     * Instantiates a new Nuxeo authentication token.
     *
     * @param principal   the principal
     * @param credentials the credentials
     * @param token
     */
    public Nuxeo2faAuthenticationToken(Object principal, Object credentials, String token) {
        super(principal, credentials);
        this.token = token;
    }

    /**
     * Instantiates a new Nuxeo authentication token.
     *
     * @param principal   the principal
     * @param credentials the credentials
     * @param authorities the authorities
     * @param token
     */
    public Nuxeo2faAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, String token) {
        super(principal, credentials, authorities);
        this.token = token;
    }

    public String getToken() {
        return token;
    }

}
