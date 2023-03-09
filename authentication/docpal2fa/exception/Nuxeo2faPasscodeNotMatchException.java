package com.wclsolution.docpal.api.security.authentication.docpal2fa.exception;

import org.springframework.security.core.AuthenticationException;

public class Nuxeo2faPasscodeNotMatchException extends AuthenticationException {
    public Nuxeo2faPasscodeNotMatchException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public Nuxeo2faPasscodeNotMatchException(String msg) {
        super(msg);
    }
}
