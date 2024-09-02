package com.ivanalimin.spring_security_jwt.config;

import com.ivanalimin.spring_security_jwt.security.JwtAuthenticationFilter;
import com.ivanalimin.spring_security_jwt.service.CustomOAuth2UserService;
import com.ivanalimin.spring_security_jwt.service.UserActionLogger;
import com.ivanalimin.spring_security_jwt.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;

import java.io.IOException;
import java.util.List;

import static org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserService userService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final UserActionLogger userActionLogger;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(request -> {
                    var corsConfiguration = new CorsConfiguration();
                    corsConfiguration.setAllowedOriginPatterns(List.of("*"));
                    corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    corsConfiguration.setAllowedHeaders(List.of("*"));
                    corsConfiguration.setAllowCredentials(true);
                    return corsConfiguration;
                }))
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers(PathRequest.toH2Console()).permitAll()//for h2 console working, not for production
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/moderator/**").hasAnyRole("MODERATOR", "ADMIN")
                        .requestMatchers("/user/**").hasAnyRole("USER", "MODERATOR", "ADMIN")
                        .anyRequest().authenticated())
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(authenticationEntryPoint())
                        .accessDeniedHandler(accessDeniedHandler()))
                .logout(logout -> logout
                        .logoutUrl("/auth/logout")
                        .addLogoutHandler(logoutHandler(userActionLogger))
                        .logoutSuccessHandler(logoutSuccessHandler(userActionLogger))
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutSuccessUrl("/auth/sign-in")
                )
                .sessionManagement(manager -> manager.sessionCreationPolicy(IF_REQUIRED))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/auth/sign-in")
                        .successHandler(authenticationSuccessHandler(userActionLogger))
                        .failureHandler(authenticationFailureHandler())
                        .defaultSuccessUrl("/home", true)
                        .failureUrl("/auth/sign-in?error=true")
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService))
                )
                .headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));//for h2 console working, not for production
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userService.getUserDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public LogoutHandler logoutHandler(UserActionLogger userActionLogger) {
        return new SecurityContextLogoutHandler() {
            @Override
            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                super.logout(request, response, authentication);
                if (authentication != null && authentication.getName() != null) {
                    userActionLogger.logUserLogout(authentication.getName());
                }
            }
        };
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(UserActionLogger userActionLogger) {

        return new SimpleUrlLogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
                if (authentication != null && authentication.getName() != null) {
                    userActionLogger.logUserLogout(authentication.getName());
                }

                if (authentication != null && authentication.getPrincipal() instanceof OAuth2User) {
                    OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
                    String provider = oauthToken.getAuthorizedClientRegistrationId();
                    if ("github".equals(provider)) {
                        // Перенаправление для отзыва доступа в GitHub
                        response.sendRedirect("https://github.com/settings/connections/applications/Ov23livm7ztrTC0cjfEH");
                        return;
                    }
                }

                super.onLogoutSuccess(request, response, authentication);
            }
        };
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(UserActionLogger userActionLogger) {
        return new SimpleUrlAuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                Authentication authentication) throws IOException, ServletException {
                String username = authentication.getName();
                userActionLogger.logUserLogin(username);
                super.onAuthenticationSuccess(request, response, authentication);
            }
        };
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationException exception) throws IOException, ServletException {
                String username = request.getParameter("username");
                userActionLogger.logFailedLogin(username, exception.getMessage());

                super.setDefaultFailureUrl("/auth/sign-in?error=true");
                super.onAuthenticationFailure(request, response, exception);
            }
        };
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                userActionLogger.logAccessDenied(auth.getName(), request.getRequestURI());
            }

            response.sendRedirect(request.getContextPath() + "/403");
        };
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            userActionLogger.logUnauthenticatedAccessAttempt(request.getRequestURI());
            response.sendRedirect(request.getContextPath() + "/auth/sign-in");
        };
    }

}
