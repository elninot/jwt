package com.wclsolution.docpal.api.security.authentication.docpal2fa;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.wclsolution.docpal.api.models.docpal.SpringSecurityAuthenticationStore;
import com.wclsolution.docpal.api.security.authentication.docpal2fa.exception.Nuxeo2faPasscodeNotMatchException;
import com.wclsolution.docpal.api.services.docpal.SpringSecurityAuthenticationStoreService;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
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
import java.util.Date;
import java.util.List;

import static com.wclsolution.docpal.api.WebSecurityConfig.ROLE_USER;


/**
 * The Nuxeo authentication provider with 2FA support
 */
@Component
@Slf4j
public class Nuxeo2faAuthenticationProvider implements AuthenticationProvider {
    @Value("${jwt.secret}")
    private String secret;
    @Value("${nuxeo.app.url}")
    private String appServerURL;

    @Value("${docpal.security.api.2fa.enable}")
    private boolean isRequired2FA;

    final SpringSecurityAuthenticationStoreService springSecurityAuthenticationStoreService;

    public Nuxeo2faAuthenticationProvider(SpringSecurityAuthenticationStoreService springSecurityAuthenticationStoreService) {
        this.springSecurityAuthenticationStoreService = springSecurityAuthenticationStoreService;
    }

    @Override
    public Authentication authenticate(@NonNull Authentication authentication) throws AuthenticationException {
        Nuxeo2faAuthenticationToken nuxeo2faAuthenticationToken = (Nuxeo2faAuthenticationToken) authentication;
        final String passcode = (String) authentication.getCredentials();

        Algorithm algorithm = Algorithm.HMAC256(secret.getBytes());
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT;
        try {
            decodedJWT = verifier.verify(nuxeo2faAuthenticationToken.getToken());
        } catch (Exception ex) {
            throw new BadCredentialsException("Nuxeo authentication failed [" + ex + "]");
        }

        String username = decodedJWT.getSubject();
        Date expiredAt = decodedJWT.getExpiresAt();
        String docPalSessionId = decodedJWT.getClaim("docPalSessionId").asString();

        // Get Nuxeo Session ID from redis
        SpringSecurityAuthenticationStore springSecurityAuthenticationStore = springSecurityAuthenticationStoreService.getSession(docPalSessionId);

        if (springSecurityAuthenticationStore == null) {
            throw new BadCredentialsException("Nuxeo authentication failed");
        }

        if (springSecurityAuthenticationStore.getPasscode() == null || !springSecurityAuthenticationStore.getPasscode().equals(passcode)) {
            throw new Nuxeo2faPasscodeNotMatchException("Incorrect Passcode=[" + passcode + "]");
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(ROLE_USER));
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, "not required", authorities);
        Nuxeo2faAuthenticationDetails authenticationDetails = new Nuxeo2faAuthenticationDetails();
        authenticationDetails.setNuxeoSessionId(springSecurityAuthenticationStore.getAuthenticationSessionId());
        token.setDetails(authenticationDetails);

        // Remove Nuxeo Session ID from redis
        springSecurityAuthenticationStoreService.deleteSession(docPalSessionId);
        return token;
    }

    @Override
    public boolean supports(@NonNull Class<?> aClass) {
//        log.info("aClass=[" + aClass.getName() + "]");
        return aClass.equals(Nuxeo2faAuthenticationToken.class);
    }
}
