package com.wclsolution.docpal.api.security;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The enum Error code.
 */
public enum ErrorCode {
    /**
     * Global error code.
     */
    GLOBAL(2),
    /**
     * Authentication error code.
     */
    AUTHENTICATION(10),
    /**
     * Jwt token expired error code.
     */
    JWT_TOKEN_EXPIRED(11),
    /**
     * Jwt token invalid error code.
     */
    JWT_TOKEN_INVALID(12);

    private final int errorCode;

    ErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * Gets error code.
     *
     * @return the error code
     */
    @JsonValue
    public int getErrorCode() {
        return errorCode;
    }
}
