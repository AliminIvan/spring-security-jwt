package com.ivanalimin.spring_security_jwt.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ivanalimin.spring_security_jwt.dto.JwtAuthenticationResponse;
import com.ivanalimin.spring_security_jwt.dto.SignInRequest;
import com.ivanalimin.spring_security_jwt.dto.SignUpRequest;
import com.ivanalimin.spring_security_jwt.model.User;
import com.ivanalimin.spring_security_jwt.service.AuthenticationService;
import com.ivanalimin.spring_security_jwt.service.JwtTokenService;
import com.ivanalimin.spring_security_jwt.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthenticationService authenticationService;

    @MockBean
    private JwtTokenService jwtTokenService;

    @MockBean
    private UserService userService;

    @Autowired
    private ObjectMapper objectMapper;

    private SignUpRequest signUpRequest;
    private SignInRequest signInRequest;
    private JwtAuthenticationResponse jwtResponse;

    @BeforeEach
    void setUp() {
        signUpRequest = new SignUpRequest("testuser", "testemail@test.com", "password123");
        signInRequest = new SignInRequest("testuser", "password123");
        jwtResponse = new JwtAuthenticationResponse("test-token");
    }

    @Test
    void signUp_ShouldReturnJwtToken() throws Exception {
        when(authenticationService.singUp(any(SignUpRequest.class))).thenReturn(jwtResponse);

        mockMvc.perform(post("/auth/sign-up")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(jwtResponse)));
    }

    @Test
    void signIn_ShouldReturnJwtToken() throws Exception {
        when(authenticationService.signIn(any(SignInRequest.class))).thenReturn(jwtResponse);

        mockMvc.perform(post("/auth/sign-in")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(jwtResponse)));
    }
}
