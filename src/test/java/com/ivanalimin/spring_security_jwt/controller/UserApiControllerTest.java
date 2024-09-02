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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserApiController.class)
@AutoConfigureMockMvc
public class UserApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    private JwtTokenService jwtTokenService;

    @Test
    @WithMockUser(roles = "ADMIN")
    void getAdminData_ShouldReturnAdminData() throws Exception {
        mockMvc.perform(get("/api/admin/data"))
                .andExpect(status().isOk())
                .andExpect(content().string("This is admin data"));
    }

    @Test
    @WithMockUser(roles = {"MODERATOR", "ADMIN"})
    void getModeratorData_ShouldReturnModeratorData() throws Exception {
        mockMvc.perform(get("/api/moderator/data"))
                .andExpect(status().isOk())
                .andExpect(content().string("This is moderator data"));
    }

    @Test
    @WithMockUser(roles = {"USER", "MODERATOR", "ADMIN"})
    void getUserData_ShouldReturnUserData() throws Exception {
        mockMvc.perform(get("/api/user/data"))
                .andExpect(status().isOk())
                .andExpect(content().string("This is user data"));
    }

    @Test
    @WithMockUser(roles = {"USER", "MODERATOR", "ADMIN"})
    void getExampleData_ShouldReturnExampleData() throws Exception {
        mockMvc.perform(get("/api/example/data"))
                .andExpect(status().isOk())
                .andExpect(content().string("This is example data"));
    }
}