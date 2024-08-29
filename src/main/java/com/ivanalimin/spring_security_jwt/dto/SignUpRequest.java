package com.ivanalimin.spring_security_jwt.dto;
//DTO для регистрации

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class SignUpRequest {

    @Size(min = 2, max = 50, message = "Username must contain from 5 to 50 characters")
    @NotBlank(message = "Username cannot be empty")
    private String username;

    @NotBlank(message = "Email address cannot be empty")
    @Email
    private String email;

    @Size(max = 255, message = "Password length must be no more than 255 characters")
    @NotBlank(message = "Password cannot be empty")
    private String password;
}
