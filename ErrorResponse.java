package com.wclsolution.docpal.api.security;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatus;

import java.time.Instant;

/**
 * The type Error response.
 */
public class ErrorResponse {
    // HTTP Response Status Code
    private final HttpStatus status;

    // General Error message
    private final String message;

    // Error code
    private final ErrorCode errorCode;

    private final Instant timestamp;

    /**
     * Instantiates a new Error response.
     *
     * @param message   the message
     * @param errorCode the error code
     * @param status    the status
     */
    protected ErrorResponse(final String message, final ErrorCode errorCode, HttpStatus status) {
        this.message = message;
        this.errorCode = errorCode;
        this.status = status;
        this.timestamp = Instant.now();
    }

    /**
     * Of error response.
     *
     * @param message   the message
     * @param errorCode the error code
     * @param status    the status
     * @return the error response
     */
    @Contract("_, _, _ -> new")
    public static @NotNull ErrorResponse of(final String message, final ErrorCode errorCode, HttpStatus status) {
        return new ErrorResponse(message, errorCode, status);
    }

    /**
     * Gets status.
     *
     * @return the status
     */
    public Integer getStatus() {
        return status.value();
    }

    /**
     * Gets message.
     *
     * @return the message
     */
    public String getMessage() {
        return message;
    }

    /**
     * Gets error code.
     *
     * @return the error code
     */
    public ErrorCode getErrorCode() {
        return errorCode;
    }

    /**
     * Gets timestamp.
     *
     * @return the timestamp
     */
    public Instant getTimestamp() {
        return timestamp;
    }
}
