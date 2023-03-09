package com.wclsolution.docpal.api.security.authentication.nuxeo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wclsolution.docpal.api.security.authentication.common.LoginRequest;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The type Nuxeo authentication filter.
 */
@Slf4j
public class NuxeoAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final ObjectMapper objectMapper;

    /**
     * Instantiates a new Nuxeo authentication filter.
     *
     * @param defaultProcessUrl the default process url
     * @param successHandler    the success handler
     * @param failureHandler    the failure handler
     * @param mapper            the mapper
     */
    public NuxeoAuthenticationFilter(
            String defaultProcessUrl, AuthenticationSuccessHandler successHandler,
            AuthenticationFailureHandler failureHandler, ObjectMapper mapper
    ) {
        super(defaultProcessUrl);
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.objectMapper = mapper;
    }

    @Override
    public Authentication attemptAuthentication(@NotNull HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        LoginRequest loginRequest = objectMapper.readValue(request.getReader(), LoginRequest.class);


        if (!StringUtils.hasLength(loginRequest.getUsername()) ||
                !StringUtils.hasLength(loginRequest.getPassword())) {
            throw new AuthenticationServiceException("Username or Password not provided");
        }

        NuxeoAuthenticationToken token = new NuxeoAuthenticationToken(
                loginRequest.getUsername(), loginRequest.getPassword()
        );
        return this.getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authentication) throws AuthenticationException, ServletException, IOException {
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request, HttpServletResponse response, AuthenticationException failed
    ) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
