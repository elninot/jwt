package com.wclsolution.docpal.api.security.authentication.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wclsolution.docpal.api.security.ErrorCode;
import com.wclsolution.docpal.api.security.ErrorResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The type Custom authentication failure handler.
 */
@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final ObjectMapper mapper;

    /**
     * Instantiates a new Custom authentication failure handler.
     *
     * @param mapper the mapper
     */
    public CustomAuthenticationFailureHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request, @NotNull HttpServletResponse response, AuthenticationException e)
            throws IOException, ServletException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if (e instanceof BadCredentialsException) {
            mapper.writeValue(response.getWriter(), ErrorResponse.of(
                    "Invalid username or password", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED)
            );
        } else if (e instanceof AuthMethodNotSupportedException) {
            mapper.writeValue(response.getWriter(), ErrorResponse.of(
                    e.getMessage(), ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED)
            );
        }
        e.printStackTrace();
        mapper.writeValue(response.getWriter(), ErrorResponse.of("Authentication failed", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
    }
}
