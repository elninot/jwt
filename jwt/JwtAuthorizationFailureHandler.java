package com.wclsolution.docpal.api.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wclsolution.docpal.api.security.ErrorCode;
import com.wclsolution.docpal.api.security.ErrorResponse;
import com.wclsolution.docpal.api.security.jwt.exception.JwtExpiredTokenException;
import com.wclsolution.docpal.api.security.jwt.exception.JwtTokenOtherException;
import com.wclsolution.docpal.api.security.jwt.exception.JwtTokenVerificationException;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The type Jwt authorization failure handler.
 */
@Component
public class JwtAuthorizationFailureHandler implements AuthenticationFailureHandler {
    private final ObjectMapper mapper;

    /**
     * Instantiates a new Jwt authorization failure handler.
     *
     * @param mapper the mapper
     */
    @Autowired
    public JwtAuthorizationFailureHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request, @NotNull HttpServletResponse response, AuthenticationException e
    ) throws IOException, ServletException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if (e instanceof JwtExpiredTokenException) {
            mapper.writeValue(
                    response.getWriter(),
                    ErrorResponse.of(e.getMessage(), ErrorCode.JWT_TOKEN_EXPIRED, HttpStatus.UNAUTHORIZED)
            );
        } else if (e instanceof JwtTokenVerificationException) {
            mapper.writeValue(
                    response.getWriter(),
                    ErrorResponse.of(e.getMessage(), ErrorCode.JWT_TOKEN_INVALID, HttpStatus.UNAUTHORIZED)
            );
        } else if (e instanceof JwtTokenOtherException) {
            mapper.writeValue(response.getWriter(), ErrorResponse.of(
                    e.getMessage(), ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED)
            );
        }
        mapper.writeValue(
                response.getWriter(),
                ErrorResponse.of("Authentication failed", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED)
        );
    }
}
