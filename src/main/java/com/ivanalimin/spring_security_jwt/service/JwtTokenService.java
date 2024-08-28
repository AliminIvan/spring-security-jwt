package com.ivanalimin.spring_security_jwt.service;

import com.ivanalimin.spring_security_jwt.security.JwtUtil;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {

    private final UserDetailsService userDetailsService;

    public JwtTokenService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public UserDetails extractUserDetailsFromToken(String token) {
        String username = JwtUtil.getClaimsFromToken(token).getSubject();
        return userDetailsService.loadUserByUsername(username);
    }
}
