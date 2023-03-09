package com.wclsolution.docpal.api.security.authentication.docpal2fa;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * The type Login request.
 */
@Data
public class Nuxeo2faRequestDTO {
    private final String passcode;

    @JsonCreator
    public Nuxeo2faRequestDTO(@JsonProperty("passcode") String passcode) {
        this.passcode = passcode;
    }
}
