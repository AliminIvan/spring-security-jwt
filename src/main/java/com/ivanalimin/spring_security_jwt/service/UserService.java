package com.ivanalimin.spring_security_jwt.service;

import com.ivanalimin.spring_security_jwt.exception_handling.NotFoundException;
import com.ivanalimin.spring_security_jwt.exception_handling.UserAlreadyExistsException;
import com.ivanalimin.spring_security_jwt.model.Role;
import com.ivanalimin.spring_security_jwt.model.User;
import com.ivanalimin.spring_security_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;
    private final UserActionLogger userActionLogger;

    private static final int MAX_FAILED_LOGIN_ATTEMPTS = 3;
    private static final long LOCK_TIME_DURATION = 15;

    public User save(User user) {
        return repository.save(user);
    }

    public User create(User user) {
        if (repository.existsByUsername(user.getUsername())) {
            throw new UserAlreadyExistsException("A user with the same name already exists");
        }
        if (repository.existsByEmail(user.getEmail())) {
            throw new UserAlreadyExistsException("A user with the same email already exists");
        }
        return save(user);
    }

    public User getByUsername(String username) {
        return repository.findByUsername(username)
                .orElseThrow(() -> new NotFoundException("User not found"));
    }

    public UserDetailsService getUserDetailsService() {
        return this::getByUsername;
    }

    public User getCurrentUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return getByUsername(username);
    }

    public void changeUserRole(String adminUsername, UUID userId, String newRole) {
        User user = repository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found"));
        user.setRole(Role.valueOf(newRole));
        repository.save(user);
        userActionLogger.logRoleChange(adminUsername, user.getUsername(), newRole);
    }

    public void getAdmin() {
        User currentUser = getCurrentUser();
        currentUser.setRole(Role.ROLE_ADMIN);
        save(currentUser);
    }

    public void increaseFailedLoginAttempts(User user) {
        int newFailedLoginAttempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(newFailedLoginAttempts);
        if (newFailedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS) {
            lockUserAccount(user);
        }
        save(user);
    }

    public void lockUserAccount(User user) {
        user.setAccountLockedUntil(LocalDateTime.now().plusMinutes(LOCK_TIME_DURATION));
        userActionLogger.logAccountLock(user.getUsername());
        save(user);
    }

    public boolean isAccountLocked(User user) {
        LocalDateTime accountLockedUntil = user.getAccountLockedUntil();
        if (accountLockedUntil == null) {
            return false;
        }
        if (accountLockedUntil.isBefore(LocalDateTime.now())) {
            user.setAccountLockedUntil(null);
            resetFailedAttempts(user);
            return false;
        }
        return true;
    }

    public void resetFailedAttempts(User user) {
        user.setFailedAttempts(0);
        save(user);
    }
}
