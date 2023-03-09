package com.wclsolution.docpal.api.security.authentication.nuxeo;

import lombok.Data;

import java.time.Instant;

/**
 * The type Nuxeo authentication details.
 */
@Data
public class NuxeoAuthenticationDetails {
    private String nuxeoSessionId;
    private Instant jwtTokenExpiredAt;
    private String userEmail;
}
