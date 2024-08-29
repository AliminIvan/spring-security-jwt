package com.ivanalimin.spring_security_jwt.exception_handling;

public class UserAlreadyExistsException extends AppException{
    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
