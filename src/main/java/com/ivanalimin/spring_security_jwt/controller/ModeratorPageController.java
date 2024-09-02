package com.ivanalimin.spring_security_jwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = ModeratorPageController.REST_URL)
@PreAuthorize("hasRole('ROLE_MODERATOR')")
public class ModeratorPageController {
    static final String REST_URL = "/moderator";

    @GetMapping("/dashboard")
    public String getModeratorDashboard() {
        return "auth/moderator-dashboard";
    }
}
