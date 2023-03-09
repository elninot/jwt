package com.wclsolution.docpal.api.security.jwtrefresh;

import lombok.Data;

import java.time.Instant;

@Data
public class JwtRefreshAuthenticationDetails {
    private String nuxeoSessionId;
    private Instant jwtTokenExpiredAt;
}
