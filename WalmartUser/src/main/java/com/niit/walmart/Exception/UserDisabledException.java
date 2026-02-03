package com.niit.walmart.Exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class UserDisabledException extends AuthenticationException {
    public UserDisabledException() {
        super("User account is disabled");
    }

    public UserDisabledException(String message) {
        super(message);
    }
}
