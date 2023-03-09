package com.wclsolution.docpal.api.security.authentication.docpal2fa;

import lombok.Data;

import java.time.Instant;

@Data
public class Nuxeo2faAuthenticationDetails {
    private String nuxeoSessionId;
    private Instant jwtTokenExpiredAt;
    private String userEmail;
}
