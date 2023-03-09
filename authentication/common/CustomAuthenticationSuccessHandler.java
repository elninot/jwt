package com.wclsolution.docpal.api.security.authentication.common;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wclsolution.docpal.api.models.docpal.SpringSecurityAuthenticationStore;
import com.wclsolution.docpal.api.models.docpal.mail.MailSendRequest;
import com.wclsolution.docpal.api.security.authentication.docpal2fa.Nuxeo2faAuthenticationDetails;
import com.wclsolution.docpal.api.security.authentication.nuxeo.NuxeoAuthenticationDetails;
import com.wclsolution.docpal.api.security.jwtrefresh.JwtRefreshAuthenticationDetails;
import com.wclsolution.docpal.api.services.docpal.SpringSecurityAuthenticationStoreService;
import com.wclsolution.docpal.api.services.mail.MailSendService;
import com.wclsolution.docpal.api.services.nuxeo.IdentityService;
import lombok.NonNull;
import org.apache.commons.text.RandomStringGenerator;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

/**
 * The type Custom authentication success handler.
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final ObjectMapper mapper;

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration.minutes}")
    private int jwtExpiresInMinutes;
    @Value("${jwt.refresh.expiration.minutes}")
    private int jwtRefreshExpiresInMinutes;
    @Value("${docpal.security.jwt.expiration.2fa.minutes}")
    private int jwt2FAExpiresInMinutes;
    @Value("${docpal.security.api.2fa.enable}")
    private boolean isRequired2FA;

    private final SpringSecurityAuthenticationStoreService springSecurityAuthenticationStoreService;
    private final MailSendService mailSendService;

    @Autowired
    private IdentityService identityService;

    /**
     * Instantiates a new Custom authentication success handler.
     *
     * @param mapper                                      the mapper
     * @param springSecurityAuthenticationStoreService
     * @param mailSendService
     */
    @Autowired
    public CustomAuthenticationSuccessHandler(final ObjectMapper mapper, SpringSecurityAuthenticationStoreService springSecurityAuthenticationStoreService, MailSendService mailSendService) {
        this.mapper = mapper;
        this.springSecurityAuthenticationStoreService = springSecurityAuthenticationStoreService;
        this.mailSendService = mailSendService;
    }

    private @NotNull Calendar getJwtExpiresAt() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, jwtExpiresInMinutes);
        return calendar;
    }

    private @NotNull Calendar getJwtRefreshExpiresAt() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, jwtRefreshExpiresInMinutes);
        return calendar;
    }

    private @NonNull Calendar get2FAJwtExpiresAt() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, jwt2FAExpiresInMinutes);
        return calendar;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        Object authenticationDetails = authentication.getDetails();
        String username = (String) authentication.getPrincipal();
        if (isRequired2FA) {
            if (authenticationDetails instanceof Nuxeo2faAuthenticationDetails)
                this.handleSuccessAndGenerateJWT(request, response, authentication);
            else if (authenticationDetails instanceof NuxeoAuthenticationDetails)
                this.handleRequestFor2fa(request, response, authentication);
            else if (authenticationDetails instanceof JwtRefreshAuthenticationDetails)
                this.handleRefreshJWT(request, response, authentication);
        } else {
            if (authenticationDetails instanceof NuxeoAuthenticationDetails)
                this.handleSuccessAndGenerateJWT(request, response, authentication);
            if (authenticationDetails instanceof JwtRefreshAuthenticationDetails)
                this.handleRefreshJWT(request, response, authentication);
        }
        try {
            // 登陆上加一层检查，查看当前登陆人以及对应的group是否跟workflow上的一一对应，如果缺少用户和group 则在workflow上进行新增，
            identityService.syncLdapUsersAndGroupsById(username);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void handleRefreshJWT(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        final JwtRefreshAuthenticationDetails authenticationDetails = (JwtRefreshAuthenticationDetails) authentication.getDetails();
        final String username = (String) authentication.getPrincipal();
        final String nuxeoSessionId = authenticationDetails.getNuxeoSessionId();
        final Collection<? extends GrantedAuthority> authorityList = authentication.getAuthorities();
        final String docPalAuthenticationSessionId = UUID.randomUUID().toString();
        Algorithm algorithm = Algorithm.HMAC256(secret.getBytes());

        Date jwtExpiredAt = getJwtExpiresAt().getTime();
        String access_token = JWT.create()
                .withSubject(username)
                .withExpiresAt(jwtExpiredAt)
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", authorityList.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .withClaim("docPalSessionId", docPalAuthenticationSessionId)
                .sign(algorithm);
        Date jwtRefreshExpiresAt = getJwtRefreshExpiresAt().getTime();
        String refresh_token = JWT.create()
                .withSubject(username)
                .withExpiresAt(jwtRefreshExpiresAt)
                .withIssuer(request.getRequestURL().toString())
                .withClaim("docPalSessionId", docPalAuthenticationSessionId)
                .sign(algorithm);

        // Write corresponding information to redis for token refresh purpose
        springSecurityAuthenticationStoreService.storeSession
                (SpringSecurityAuthenticationStore.builder()
                        .docPalAuthenticationSessionId(docPalAuthenticationSessionId)
                        .authenticationSessionId(nuxeoSessionId)
                        .enabled(true)
                        .expiredDate(jwtRefreshExpiresAt)
                        .build());
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        tokens.put("accessTokenExpiry", String.valueOf(jwtExpiredAt.getTime()));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(APPLICATION_JSON_VALUE);
        mapper.writeValue(response.getWriter(), tokens);

        clearAuthenticationAttributes(request);
    }

    // Handle Login and ask for 2FA
    private void handleRequestFor2fa(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        final Object authenticationDetails = authentication.getDetails();
        if (!(authenticationDetails instanceof NuxeoAuthenticationDetails)) {
            throw new IOException("Internal Error");
        }
        final String username = (String) authentication.getPrincipal();
        final NuxeoAuthenticationDetails nuxeoAuthenticationDetails = (NuxeoAuthenticationDetails) authenticationDetails;
        final String docPalAuthenticationSessionId = UUID.randomUUID().toString();
        final Date jwtExpiredAt = this.get2FAJwtExpiresAt().getTime();

        Algorithm algorithm = Algorithm.HMAC256(secret.getBytes());
        final String access_token = JWT.create()
                .withSubject(username)
                .withExpiresAt(jwtExpiredAt)
                .withIssuer(request.getRequestURL().toString())
                .withClaim("docPalSessionId", docPalAuthenticationSessionId)
                .sign(algorithm);
        final String email = nuxeoAuthenticationDetails.getUserEmail();
        if (email == null || email.isBlank() || email.isEmpty() || !email.contains("@")) {
            throw new IOException("User without email, username=[" + username + "]");
        }

        // Generate Passcode
        RandomStringGenerator passcode = new RandomStringGenerator.Builder().withinRange('0', '9').build();
        String passcodeString = passcode.generate(6);

        // Write corresponding information to redis for token refresh purpose
        springSecurityAuthenticationStoreService.storeSession
                (SpringSecurityAuthenticationStore.builder()
                        .docPalAuthenticationSessionId(docPalAuthenticationSessionId)
                        .authenticationSessionId(((NuxeoAuthenticationDetails) authentication.getDetails()).getNuxeoSessionId())
                        .enabled(true)
                        .expiredDate(jwtExpiredAt)
                        .passcode(passcodeString)
                        .build());
        // Send Email
        mailSendService.sendText(MailSendRequest.builder()
                .to(email)
                .subject("Passcode from DocPal")
                .text(passcodeString)
                .build());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("isRequired2FA", "true");
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(APPLICATION_JSON_VALUE);
        mapper.writeValue(response.getWriter(), tokens);

        clearAuthenticationAttributes(request);
    }

    // Handle Login Success without 2FA
    private void handleSuccessAndGenerateJWT(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String username = (String) authentication.getPrincipal();
        final String docPalAuthenticationSessionId = UUID.randomUUID().toString();

        Algorithm algorithm = Algorithm.HMAC256(secret.getBytes());
        String access_token;
        String nuxeoSessionId;
        if (authentication.getDetails() instanceof NuxeoAuthenticationDetails) {
            nuxeoSessionId = ((NuxeoAuthenticationDetails) authentication.getDetails()).getNuxeoSessionId();
        } else if (authentication.getDetails() instanceof Nuxeo2faAuthenticationDetails) {
            nuxeoSessionId = ((Nuxeo2faAuthenticationDetails) authentication.getDetails()).getNuxeoSessionId();
        } else {
            throw new IOException("Internal Error");
        }

        Date jwtExpiredAt = getJwtExpiresAt().getTime();
        access_token = JWT.create()
                .withSubject(username)
                .withExpiresAt(jwtExpiredAt)
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .withClaim("docPalSessionId", docPalAuthenticationSessionId)
                .sign(algorithm);

        Date jwtRefreshExpiresAt = getJwtRefreshExpiresAt().getTime();
        String refresh_token = JWT.create()
                .withSubject(username)
                .withExpiresAt(jwtRefreshExpiresAt)
                .withIssuer(request.getRequestURL().toString())
                .withClaim("docPalSessionId", docPalAuthenticationSessionId)
                .sign(algorithm);

        springSecurityAuthenticationStoreService.storeSession
                (SpringSecurityAuthenticationStore.builder()
                        .docPalAuthenticationSessionId(docPalAuthenticationSessionId)
                        .authenticationSessionId(nuxeoSessionId)
                        .enabled(true)
                        .expiredDate(jwtExpiredAt)
                        .build());
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        tokens.put("accessTokenExpiry", String.valueOf(jwtExpiredAt.getTime()));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(APPLICATION_JSON_VALUE);
        mapper.writeValue(response.getWriter(), tokens);

        clearAuthenticationAttributes(request);
    }

    /**
     * Removes temporary authentication-related data which may have been stored
     * in the session during the authentication process..
     *
     * @param request the request
     */
    protected final void clearAuthenticationAttributes(@NotNull HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }

        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
}
