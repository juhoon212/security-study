package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig{


    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")

                .anyRequest().authenticated();
        // 로그인 성공 후 핸들러
        // 로그인 실패 후 핸들러
        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response); //사용자가 가고자 했던 URL 정보 session에 담고있음
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                });
        http
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() { // 인증 예외처리
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() { // 인가 예외 처리
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });
//                .sessionManagement()
////                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // 필요할떄만 생성(디폴트)
//                // SessionCreationPolicy.Stateless => JWT 방식 채택 시 사용
////                .sessionFixation().changeSessionId(); // 접속할때마다 세션아이디 생성으로 공격자의 침입 방지
//                .maximumSessions(1) // 최대 로그인 세션 가능
//                .maxSessionsPreventsLogin(true); // true 이면 세션이 초과되면 새로 로그인 못하게함
//                                                    // false 이면 전의 로그인 사용자의 세션 만료시켜버림

//        http
//                .csrf().disable(); csrf 끄기



        return http.build();
    }

//    @Bean
//    public UserDetailsManager users() {
//        UserDetails user = User.builder()
//                .username("user")
//                .password("{noop}1111")
//                .roles("USER")
//                .build();
//        UserDetails sys = User.builder()
//                .username("sys")
//                .password("{noop}1111")
//                .roles("SYS")
//                .build();
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password("{noop}1111")
//                .roles("ADMIN", "SYS", "USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user, sys, admin); // 신버전 유저 인메모리로 생성하는법
//    }
}
