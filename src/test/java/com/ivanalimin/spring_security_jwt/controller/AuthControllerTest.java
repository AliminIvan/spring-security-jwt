package com.ivanalimin.spring_security_jwt.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ivanalimin.spring_security_jwt.dto.JwtAuthenticationResponse;
import com.ivanalimin.spring_security_jwt.dto.SignInRequest;
import com.ivanalimin.spring_security_jwt.dto.SignUpRequest;
import com.ivanalimin.spring_security_jwt.service.AuthenticationService;
import com.ivanalimin.spring_security_jwt.service.JwtTokenService;
import com.ivanalimin.spring_security_jwt.service.UserService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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

    @Test
    public void testSignUp() throws Exception {
        SignUpRequest request = new SignUpRequest("testuser", "test@example.com", "password");
        JwtAuthenticationResponse response = new JwtAuthenticationResponse("jwt-token");

        Mockito.when(authenticationService.singUp(Mockito.any(SignUpRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/sign-up")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token"));
    }

    @Test
    public void testSignIn() throws Exception {
        SignInRequest request = new SignInRequest("testuser", "password");
        JwtAuthenticationResponse response = new JwtAuthenticationResponse("jwt-token");

        Mockito.when(authenticationService.signIn(Mockito.any(SignInRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/sign-in")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token"));
    }
}
