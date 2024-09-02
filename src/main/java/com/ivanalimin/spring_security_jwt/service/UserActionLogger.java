package com.ivanalimin.spring_security_jwt.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class UserActionLogger {

    public void logUserLogin(String username) {
        log.info("User {} has logged in", username);
    }

    public void logUserLogout(String username) {
        log.info("User {} has logged out", username);
    }

    public void logUserRegister(String username) {
        log.info("User {} has registered", username);
    }

    public void logRoleChange(String adminUsername, String targetUsername, String newRole) {
        log.info("Admin {} changed role of user {} to {}", adminUsername, targetUsername, newRole);
    }

    public void logAccountLock(String username) {
        log.info("User {} has account lock", username);
    }

    public void logFailedLogin(String username, String reason) {
        log.info("User {} failed to login. Reason {}", username, reason);
    }

    public void logAccessDenied(String username, String uri) {
        log.info("User {} access denied. URI {}", username, uri);
    }

    public void logUnauthenticatedAccessAttempt(String uri) {
        log.info("User {} unauthenticated access attempt. URI {}", uri, uri);
    }
}
