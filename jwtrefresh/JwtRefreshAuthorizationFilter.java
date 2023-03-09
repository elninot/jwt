package com.wclsolution.docpal.api.security.jwtrefresh;

import com.sun.istack.NotNull;

import com.wclsolution.docpal.api.security.jwt.JwtAuthenticationToken;
import com.wclsolution.docpal.api.security.jwt.exception.JwtTokenMissingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * The type Jwt authorization filter.
 */
@Slf4j
public class JwtRefreshAuthorizationFilter extends AbstractAuthenticationProcessingFilter {
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    /**
     * Instantiates a new Jwt authorization filter.
     *
     * @param failureHandler the failure handler
     * @param successHandler
     */
    public JwtRefreshAuthorizationFilter( String defaultProcessUrl, AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler) {
        super(defaultProcessUrl);
        this.failureHandler = failureHandler;
        this.successHandler = successHandler;
    }

    @Override
    public Authentication attemptAuthentication(@NotNull HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        final String authorizationHeader = request.getHeader(AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new JwtTokenMissingException("No JWT token found in request headers");
        }

        String token = authorizationHeader.substring("Bearer ".length());
        return getAuthenticationManager().authenticate(new JwtAuthenticationToken(token));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed
    ) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
