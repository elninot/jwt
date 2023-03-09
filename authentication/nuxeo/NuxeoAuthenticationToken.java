package com.wclsolution.docpal.api.security.authentication.nuxeo;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * The type Nuxeo authentication token.
 */
public class NuxeoAuthenticationToken extends UsernamePasswordAuthenticationToken {
    /**
     * Instantiates a new Nuxeo authentication token.
     *
     * @param principal   the principal
     * @param credentials the credentials
     */
    public NuxeoAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    /**
     * Instantiates a new Nuxeo authentication token.
     *
     * @param principal   the principal
     * @param credentials the credentials
     * @param authorities the authorities
     */
    public NuxeoAuthenticationToken(
            Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities
    ) {
        super(principal, credentials, authorities);
    }
}
