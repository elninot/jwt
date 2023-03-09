package com.wclsolution.docpal.api.security.jwtrefresh;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.wclsolution.docpal.api.models.docpal.SpringSecurityAuthenticationStore;
import com.wclsolution.docpal.api.security.authentication.nuxeo.CustomBasicAuthInterceptor;
import com.wclsolution.docpal.api.security.jwt.JwtAuthenticationToken;
import com.wclsolution.docpal.api.security.jwt.exception.JwtExpiredTokenException;
import com.wclsolution.docpal.api.security.jwt.exception.JwtTokenOtherException;
import com.wclsolution.docpal.api.security.jwt.exception.JwtTokenVerificationException;
import com.wclsolution.docpal.api.services.docpal.SpringSecurityAuthenticationStoreService;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.nuxeo.client.HttpHeaders;
import org.nuxeo.client.NuxeoClient;
import org.nuxeo.client.objects.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
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
 * The type Jwt authentication provider.
 */
@Component
@Slf4j
public class JwtRefreshAuthenticationProvider implements AuthenticationProvider {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${nuxeo.app.url}")
    private String appServerURL;

    final SpringSecurityAuthenticationStoreService springSecurityAuthenticationStoreService;

    public JwtRefreshAuthenticationProvider(SpringSecurityAuthenticationStoreService springSecurityAuthenticationStoreService) {
        this.springSecurityAuthenticationStoreService = springSecurityAuthenticationStoreService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier verifier  = JWT.require(algorithm).build();
        try {
            DecodedJWT decodedJWT = verifier.verify(jwtAuthenticationToken.getToken());

            String username = decodedJWT.getSubject();
            Date expiredAt = decodedJWT.getExpiresAt();
            String docPalSessionId = decodedJWT.getClaim("docPalSessionId").asString();

            // Get Nuxeo Session ID from Redis
            SpringSecurityAuthenticationStore springSecurityAuthenticationStore = springSecurityAuthenticationStoreService.getSession(docPalSessionId);
            CustomBasicAuthInterceptor customBasicAuthInterceptor = new CustomBasicAuthInterceptor(springSecurityAuthenticationStore.getAuthenticationSessionId());
            NuxeoClient nuxeoClient = new NuxeoClient.Builder()
                    .url(appServerURL)
                    .authentication(customBasicAuthInterceptor)
                    .header(HttpHeaders.NX_ES_SYNC, true)
                    .connect();
            User user = nuxeoClient.userManager().fetchUser(username);

//            log.info("Nuxeo Current Username=[" + nuxeoClient.getCurrentUser().getUserName() + "]");
            final String sessionId = customBasicAuthInterceptor.getToken();
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(ROLE_USER));
            JwtRefreshAuthenticationDetails jwtRefreshAuthenticationDetails = new JwtRefreshAuthenticationDetails();
            jwtRefreshAuthenticationDetails.setNuxeoSessionId(sessionId);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, "null", authorities);
            authenticationToken.setDetails(jwtRefreshAuthenticationDetails);

            springSecurityAuthenticationStoreService.deleteSession(docPalSessionId);

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
    public boolean supports(@NonNull Class<?> authentication) {
//        log.info("aClass=[" + authentication.getName() + "]");
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
