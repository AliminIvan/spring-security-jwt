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

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;

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

    public void getAdmin() {
        User currentUser = getCurrentUser();
        currentUser.setRole(Role.ROLE_ADMIN);
        save(currentUser);
    }
}
