package com.ivanalimin.spring_security_jwt.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class UserActionLogger {

    public void logUserLogin(String username) {
        log.info("User {} has logged in", username);
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
}
