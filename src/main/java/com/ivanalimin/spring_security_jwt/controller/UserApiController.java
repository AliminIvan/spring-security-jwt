package com.ivanalimin.spring_security_jwt.controller;

import com.ivanalimin.spring_security_jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.UUID;

@RestController
@RequestMapping(value = UserApiController.REST_URL)
@RequiredArgsConstructor
public class UserApiController {
    static final String REST_URL = "/api";
    private final UserService service;

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/data")
    public ResponseEntity<String> getAdminData() {
        return ResponseEntity.ok("This is admin data");
    }

    @PreAuthorize("hasAnyRole('MODERATOR', 'ADMIN')")
    @GetMapping("/moderator/data")
    public ResponseEntity<String> getModeratorData() {
        return ResponseEntity.ok("This is moderator data");
    }

    @PreAuthorize("hasAnyRole('USER', 'MODERATOR', 'ADMIN')")
    @GetMapping("/user/data")
    public ResponseEntity<String> getUserData() {
        return ResponseEntity.ok("This is user data");
    }

    @GetMapping("/example/data")
    public ResponseEntity<String> getExampleData() {
        return ResponseEntity.ok("This is example data");
    }

    @PutMapping("/{userId}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> changeUserRole(
            @PathVariable UUID userId,
            @RequestParam String newRole,
            Principal principal) {
        String adminUsername = principal.getName();
        service.changeUserRole(adminUsername, userId, newRole);
        return ResponseEntity.ok("User role updated successfully");
    }
}
