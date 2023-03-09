package com.wclsolution.docpal.api.security.authentication.wclserver;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public class WCLServerAuthenticationToken extends UsernamePasswordAuthenticationToken {
    public WCLServerAuthenticationToken(String username, String password, List<GrantedAuthority> authorities) {
        super(username, password, authorities);
    }
}
