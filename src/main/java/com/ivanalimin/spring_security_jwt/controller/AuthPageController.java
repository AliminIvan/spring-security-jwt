package com.ivanalimin.spring_security_jwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = AuthPageController.REST_URL)
@RequiredArgsConstructor
public class AuthPageController {
    static final String REST_URL = "/auth";

    @GetMapping("/sign-in")
    public String showLoginPage(Model model) {
        return "auth/sign-in";
    }

    @GetMapping("/auth/sign-in?error=true")
    public String showLoginErrorPage(Model model) {
        model.addAttribute("loginError", true);
        return "auth/sign-in";
    }

    @GetMapping("/sign-up")
    public String showSignUpPage(Model model) {
        return "auth/sign-up";
    }
}
