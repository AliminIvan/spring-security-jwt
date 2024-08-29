package com.ivanalimin.spring_security_jwt.controller;

import com.ivanalimin.spring_security_jwt.service.JwtTokenService;
import com.ivanalimin.spring_security_jwt.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ExampleController.class)
@AutoConfigureMockMvc
public class ExampleControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    JwtTokenService jwtTokenService;

    @Test
    @WithMockUser
    public void testExample() throws Exception {
        mockMvc.perform(get("/example"))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, world!"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testExampleAdmin() throws Exception {
        mockMvc.perform(get("/example/admin"))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, admin!"));
    }

    @Test
    @WithMockUser
    public void testGetAdmin() throws Exception {
        mockMvc.perform(get("/example/get-admin"))
                .andExpect(status().isOk());

        verify(userService).getAdmin();
    }
}