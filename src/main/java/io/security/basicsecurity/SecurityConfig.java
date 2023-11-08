package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
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
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")

                .anyRequest().authenticated();
        // 로그인 성공 후 핸들러
        // 로그인 실패 후 핸들러
        http
                .formLogin();
        http
                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // 필요할떄만 생성(디폴트)
                // SessionCreationPolicy.Stateless => JWT 방식 채택 시 사용
//                .sessionFixation().changeSessionId(); // 접속할때마다 세션아이디 생성으로 공격자의 침입 방지
                .maximumSessions(1) // 최대 로그인 세션 가능
                .maxSessionsPreventsLogin(true); // true 이면 세션이 초과되면 새로 로그인 못하게함
//                                                    // false 이면 전의 로그인 사용자의 세션 만료시켜버림





        return http.build();
    }

    @Bean
    public UserDetailsManager users() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();
        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER")
                .build();

        return new InMemoryUserDetailsManager(user, sys, admin); // 신버전 유저 인메모리로 생성하는법
    }
}
