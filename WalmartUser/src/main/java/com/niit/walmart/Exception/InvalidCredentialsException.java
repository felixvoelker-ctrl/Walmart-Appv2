package com.niit.walmart.Exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidCredentialsException extends AuthenticationException {
    public InvalidCredentialsException() {
        super("Invalid username or password");
    }

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
