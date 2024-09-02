package com.ivanalimin.spring_security_jwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = AdminPageController.REST_URL)
@PreAuthorize("hasRole('ROLE_ADMIN')")
public class AdminPageController {
    static final String REST_URL = "/admin";

    @GetMapping("/dashboard")
    public String getAdminDashboard() {
        return "auth/admin-dashboard";
    }
}
