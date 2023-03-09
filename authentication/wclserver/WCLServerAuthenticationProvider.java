package com.wclsolution.docpal.api.security.authentication.wclserver;

import com.wclsolution.docpal.api.RegisteredServers;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
@Slf4j
public class WCLServerAuthenticationProvider implements AuthenticationProvider {
    private RegisteredServers registeredServers;

    public WCLServerAuthenticationProvider(RegisteredServers registeredServers) {
        this.registeredServers = registeredServers;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String serverName = authentication.getName();
        String serverKey = (String) authentication.getCredentials();
        log.debug("authentication: " + authentication + serverName + serverKey);
        log.debug("registeredservers: " + registeredServers);
        String requestedServerKey = registeredServers.getKey().get(serverName);
        log.debug("requestedServerKey=" + requestedServerKey);
        if (!serverKey.equals(requestedServerKey))
            throw new BadCredentialsException("The server key is not registered") {
            };
        List<GrantedAuthority> authorities = Stream.of("ROLE_USER").map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new WCLServerAuthenticationToken(serverName, serverKey, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (WCLServerAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
