package com.ivanalimin.spring_security_jwt.controller;

import com.ivanalimin.spring_security_jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = ExampleController.REST_URL)
@RequiredArgsConstructor
public class ExampleController {
    static final String REST_URL = "/example";
    private final UserService service;

    @GetMapping
    public String example() {
        return "Hello, world!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String exampleAdmin() {
        return "Hello, admin!";
    }

    @GetMapping("/get-admin")
    public void getAdmin() {
        service.getAdmin();
    }
}
