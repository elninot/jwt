package com.wclsolution.docpal.api.security.authentication.nuxeo;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.nuxeo.client.NuxeoClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

import static com.wclsolution.docpal.api.WebSecurityConfig.ROLE_USER;

/**
 * The type Nuxeo authentication provider.
 */
@Component
@Slf4j
public class NuxeoAuthenticationProvider implements AuthenticationProvider {
    @Value("${nuxeo.app.url}")
    private String appServerURL;

    @Override
    public Authentication authenticate(@NotNull Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

//        log.debug("Login with username=[" + username + "], password=[" + password + "]");
        if (username == null || password == null || username.isEmpty() || password.isEmpty()) {
            throw new BadCredentialsException("Missing password");
        }

        try {
//            log.debug("Try to login nuxeo with url=[" + appServerURL + "]");
            CustomBasicAuthInterceptor customBasicAuthInterceptor = new CustomBasicAuthInterceptor(username, password);
            NuxeoClient nuxeoClient = new NuxeoClient.Builder()
                    .url(appServerURL)
                    .authentication(customBasicAuthInterceptor)
                    .connect();
//            log.info("Nuxeo Current Username=[" + nuxeoClient.getCurrentUser().getUserName() + "]");

            String sessionId = customBasicAuthInterceptor.getToken();

            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(ROLE_USER));
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password, authorities);
            NuxeoAuthenticationDetails authenticationDetails = new NuxeoAuthenticationDetails();
            authenticationDetails.setNuxeoSessionId(sessionId);
            token.setDetails(authenticationDetails);
            return token;
        } catch (Exception ex) {
            throw new BadCredentialsException("Nuxeo authentication failed [" + ex + "]");
        }
    }

    @Override
    public boolean supports(@NotNull Class<?> aClass) {
//        log.info("aClass=[" + aClass.getName() + "]");
        return aClass.equals(NuxeoAuthenticationToken.class);
    }
}
