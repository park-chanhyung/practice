package com.mysite.pch.config;

import com.mysite.pch.user.UserRole;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig  {

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                // 인증
                                .requestMatchers("/security-login/info").authenticated()
                                //인가
                                .requestMatchers("/security-login/admin/**").hasAuthority(UserRole.ADMIN.name())
                                .anyRequest().permitAll())
                .formLogin((formLogin)->formLogin
                        .usernameParameter("loginId")
                        .passwordParameter("password")
                        //로그인 페이지 URL
                        .loginPage("/security-login/login")
                        //로그인 성공 시 이동할 URL
                        .defaultSuccessUrl("/security-login")
                        //로그인 실패 시 이동할 URL
                        .failureUrl("/security-login/login"))

                .logout((logout)->logout
                        .logoutSuccessUrl("/security-login/logout")
                        .invalidateHttpSession(true).deleteCookies("JSESSIONID")
                );
        return http.build();
    }
}