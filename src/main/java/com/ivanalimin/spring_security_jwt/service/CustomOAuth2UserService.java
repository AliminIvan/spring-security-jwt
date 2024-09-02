package com.ivanalimin.spring_security_jwt.service;

import com.ivanalimin.spring_security_jwt.exception_handling.NotFoundException;
import com.ivanalimin.spring_security_jwt.model.Role;
import com.ivanalimin.spring_security_jwt.model.User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserService userService;

    public CustomOAuth2UserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        String name = oAuth2User.getAttribute("name");
        if (name == null) {
            throw new OAuth2AuthenticationException("Name not found from OAuth2 provider");
        }

        User user;
        try {
            user = userService.getByUsername(name);
        } catch (NotFoundException e) {
            user = User.builder()
                    .username(name)
                    .email(oAuth2User.getAttribute("email"))
                    .role(Role.ROLE_USER)
                    .password("")
                    .failedAttempts(0)
                    .build();
            user = userService.save(user);
        }

        return new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority(user.getRole().name())),
                oAuth2User.getAttributes(),
                "name"
        );
    }
}
