package com.ivanalimin.spring_security_jwt.service;

import com.ivanalimin.spring_security_jwt.dto.JwtAuthenticationResponse;
import com.ivanalimin.spring_security_jwt.dto.SignInRequest;
import com.ivanalimin.spring_security_jwt.dto.SignUpRequest;
import com.ivanalimin.spring_security_jwt.model.Role;
import com.ivanalimin.spring_security_jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserService userService;
    private final JwtTokenService jwtTokenService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationResponse singUp(SignUpRequest request) {
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ROLE_USER)
                .build();
        userService.create(user);
        String token = jwtTokenService.generateToken(user);
        return new JwtAuthenticationResponse(token);
    }

    public JwtAuthenticationResponse signIn(SignInRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
        ));
        UserDetails user = userService.getUserDetailsService().loadUserByUsername(request.getUsername());
        String token = jwtTokenService.generateToken(user);
        return new JwtAuthenticationResponse(token);
    }
}
