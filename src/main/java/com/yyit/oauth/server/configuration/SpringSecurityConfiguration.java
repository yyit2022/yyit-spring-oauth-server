package com.yyit.oauth.server.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * <p>
 * spring security 配置
 * </p>
 *
 * @author yyit
 * @date 2022/4/7
 **/
@EnableWebSecurity
public class SpringSecurityConfiguration {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .oauth2ResourceServer()
                .jwt();

        return http.build();
    }


    @Bean
    public UserDetailsService users(PasswordEncoder encoder) {
        UserDetails user = User.builder()
                .authorities(List.of())
                .username("admin")
                .password(encoder.encode("password"))
                .roles("ADMIN")
                .build();

        UserDetails user1 = User.builder()
                .authorities(List.of())
                .username("user")
                .password(encoder.encode("123"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user, user1);
    }

}
