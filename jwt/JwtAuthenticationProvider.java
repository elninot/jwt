package com.wclsolution.docpal.api.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.wclsolution.docpal.api.models.docpal.SpringSecurityAuthenticationStore;
import com.wclsolution.docpal.api.security.authentication.nuxeo.NuxeoAuthenticationDetails;
import com.wclsolution.docpal.api.security.jwt.exception.JwtExpiredTokenException;
import com.wclsolution.docpal.api.security.jwt.exception.JwtTokenOtherException;
import com.wclsolution.docpal.api.security.jwt.exception.JwtTokenVerificationException;
import com.wclsolution.docpal.api.services.docpal.SpringSecurityAuthenticationStoreService;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import static java.util.Arrays.stream;

/**
 * The type Jwt authentication provider.
 */
@Component
@Slf4j
public class JwtAuthenticationProvider implements AuthenticationProvider {
    @Value("${jwt.secret}")
    private String secret;

    final SpringSecurityAuthenticationStoreService springSecurityAuthenticationStoreService;

    public JwtAuthenticationProvider(SpringSecurityAuthenticationStoreService springSecurityAuthenticationStoreService) {
        this.springSecurityAuthenticationStoreService = springSecurityAuthenticationStoreService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;

        try {
            Algorithm algorithm = Algorithm.HMAC256(secret.getBytes());
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(jwtAuthenticationToken.getToken());

            String username = decodedJWT.getSubject();
            Date expiredAt = decodedJWT.getExpiresAt();

            String docPalSessionId = decodedJWT.getClaim("docPalSessionId").asString();
            String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));

            // Get Nuxeo Session ID from redis
            SpringSecurityAuthenticationStore springSecurityAuthenticationStore = springSecurityAuthenticationStoreService.getSession(docPalSessionId);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
            NuxeoAuthenticationDetails nuxeoAuthenticationDetails = new NuxeoAuthenticationDetails();
            nuxeoAuthenticationDetails.setNuxeoSessionId(springSecurityAuthenticationStore.getAuthenticationSessionId());
            nuxeoAuthenticationDetails.setJwtTokenExpiredAt(expiredAt.toInstant());
            authenticationToken.setDetails(nuxeoAuthenticationDetails);

            return authenticationToken;
        } catch (SignatureVerificationException ex) {
            throw new JwtTokenVerificationException("Token Signature Verification Failed.");
        } catch (TokenExpiredException ex) {
            throw new JwtExpiredTokenException(ex.getMessage());
        } catch (Exception ex) {
            throw new JwtTokenOtherException("Error in token");
        }
    }

    @Override
    public boolean supports(@NotNull Class<?> authentication) {
//        log.info("aClass=[" + authentication.getName() + "]");
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
