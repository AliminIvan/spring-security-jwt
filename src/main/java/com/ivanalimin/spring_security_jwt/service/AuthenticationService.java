package com.ivanalimin.spring_security_jwt.service;

import com.ivanalimin.spring_security_jwt.dto.JwtAuthenticationResponse;
import com.ivanalimin.spring_security_jwt.dto.SignInRequest;
import com.ivanalimin.spring_security_jwt.dto.SignUpRequest;
import com.ivanalimin.spring_security_jwt.model.Role;
import com.ivanalimin.spring_security_jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserService userService;
    private final JwtTokenService jwtTokenService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserActionLogger userActionLogger;

    public JwtAuthenticationResponse singUp(SignUpRequest request) {
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ROLE_USER)
                .build();
        userService.create(user);
        String token = jwtTokenService.generateToken(user);
        userActionLogger.logUserRegister(request.getUsername());
        return new JwtAuthenticationResponse(token);
    }

    public JwtAuthenticationResponse signIn(SignInRequest request) {
        User user = (User) userService.getUserDetailsService().loadUserByUsername(request.getUsername());
        if (userService.isAccountLocked(user)) {
            throw new LockedException("Account is locked until: " + user.getAccountLockedUntil());
        }
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
            ));
        } catch (BadCredentialsException exception) {
            userService.increaseFailedLoginAttempts(user);
            throw exception;
        }
        String token = jwtTokenService.generateToken(user);
        userActionLogger.logUserLogin(request.getUsername());
        return new JwtAuthenticationResponse(token);
    }
}
