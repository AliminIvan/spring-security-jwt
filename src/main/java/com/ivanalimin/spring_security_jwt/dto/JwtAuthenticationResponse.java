package com.ivanalimin.spring_security_jwt.dto;
//DTO для передачи токена пользователю

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class JwtAuthenticationResponse {
    private String token;
}
