package com.ivanalimin.spring_security_jwt.controller;

import com.ivanalimin.spring_security_jwt.dto.JwtAuthenticationResponse;
import com.ivanalimin.spring_security_jwt.dto.SignInRequest;
import com.ivanalimin.spring_security_jwt.dto.SignUpRequest;
import com.ivanalimin.spring_security_jwt.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = AuthController.REST_URL)
@RequiredArgsConstructor
public class AuthController {
    static final String REST_URL = "/auth";

    private final AuthenticationService service;

    @PostMapping("/sign-up")
    public JwtAuthenticationResponse signUp(@RequestBody @Valid SignUpRequest signUpRequest) {
        return service.singUp(signUpRequest);
    }

    @PostMapping("/sign-in")
    public JwtAuthenticationResponse signIn(@RequestBody @Valid SignInRequest signInRequest) {
        return service.signIn(signInRequest);
    }
}
