package com.mysite.pch.config;

import com.mysite.pch.JWT.JwtTokenFilter;
import com.mysite.pch.user.UserRole;
import com.mysite.pch.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class JWTSecurityConfig {

    private final UserService userService;
    private static String secretKey = "my-secret-key-123123";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // HTTP Basic 인증을 비활성화
                .httpBasic(HttpBasicConfigurer::disable)
                // CSRF 보호를 비활성화
                .csrf(AbstractHttpConfigurer::disable)
                // 세션 관리를 STATELESS로 설정하여 세션을 사용x
                .sessionManagement((sessionManagement) ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtTokenFilter(userService, secretKey), UsernamePasswordAuthenticationFilter.class)
                //.authorizeRequests()는 요청에 대한 권한을 설정하는 메서드
                //jwt 권한 있는 사람만 내정보 info 확인가능
                //admin 계정만 admin페이지 가능
                // 나머지 모든 요청은 다 허용
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/jwt-login/info").authenticated()
                                .requestMatchers("/jwt-login/admin/**").hasAuthority(UserRole.ADMIN.name())
                                .anyRequest().permitAll()
                )
          //    jwt-login(화면)에서 인증에 실패하면 에러 페이지로 redirect
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling
                                // 인증에 실패한 경우 처리
                                .authenticationEntryPoint((request, response, authException) -> {
                                    // jwt-login(화면)에서 인증에 실패하면 에러 페이지로 redirect
                                    if (!request.getRequestURI().contains("api")) {
                                        response.sendRedirect("/jwt-login/authentication-fail");
                                    }
                                })
                                // 인가에 실패한 경우 처리
                                .accessDeniedHandler((request, response, accessDeniedException) -> {
                                    //권한 x 로 에러 페이지
                                    if (!request.getRequestURI().contains("api")) {
                                        response.sendRedirect("/jwt-login/authorization-fail");
                                    }
                                })
                )

                .build();
    }
}