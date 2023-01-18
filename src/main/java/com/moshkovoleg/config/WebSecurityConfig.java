package com.moshkovoleg.config;

import com.moshkovoleg.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig  {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/products/**").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder getEncoder(){
        return new BCryptPasswordEncoder(16);
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user =
                User.builder()
                .username("user")
                .password(getEncoder().encode("pass"))
                .authorities(Role.USER.getAuthorities())
                .build();

        UserDetails admin =
                User.builder()
                        .username("admin")
                        .password(getEncoder().encode("pass"))
                        .authorities(Role.ADMIN.getAuthorities())
                        .build();

        return new InMemoryUserDetailsManager(user,admin);
    }
}
