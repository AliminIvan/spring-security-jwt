package com.ivanalimin.spring_security_jwt.controller;

import com.ivanalimin.spring_security_jwt.model.User;
import com.ivanalimin.spring_security_jwt.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = UserPageController.REST_URL)
@PreAuthorize("hasRole('ROLE_USER')")
public class UserPageController {
    static final String REST_URL = "/user";
    private final UserService userService;

    public UserPageController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/profile")
    public String getUserProfile(Model model, @AuthenticationPrincipal OAuth2User oAuth2User) {
        String name = oAuth2User.getAttribute("name");
        User user = userService.getByUsername(name);
        model.addAttribute("user", user);
        return "auth/user-profile";
    }
}
