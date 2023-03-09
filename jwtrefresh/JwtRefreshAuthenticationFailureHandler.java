package com.wclsolution.docpal.api.security.jwtrefresh;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.wclsolution.docpal.api.security.ErrorCode;
import com.wclsolution.docpal.api.security.ErrorResponse;
import lombok.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The type Custom authentication failure handler.
 */
@Component
public class JwtRefreshAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final ObjectMapper mapper;

    /**
     * Instantiates a new Custom authentication failure handler.
     *
     * @param mapper the mapper
     */
    public JwtRefreshAuthenticationFailureHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, @NonNull HttpServletResponse response, AuthenticationException e) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        response.setStatus(HttpStatus.FORBIDDEN.value());
        mapper.writeValue(response.getWriter(), ErrorResponse.of("Refresh token failed", ErrorCode.AUTHENTICATION, HttpStatus.FORBIDDEN));
    }
}
