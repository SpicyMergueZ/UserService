package com.example.userservice.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.example.userservice.filter.CustomAuthenticationFilter;

import jakarta.security.auth.message.config.AuthConfig;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    // private final UserDetailsService userDetailsService;
    // private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /*
     * @Bean
     * public void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 
     * auth.userDetailsService(userDetailsService).passwordEncoder(
     * bCryptPasswordEncoder);
     * 
     * }
     * 
     * 
     * private PasswordEncoder passwordEncoder() {
     * return new BCryptPasswordEncoder();
     * }
     * 
     * @Bean
     * public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
     * Exception {
     * 
     * http.csrf().disable()
     * .authorizeRequests()
     * .anyRequest().authenticated()
     * .and()
     * .httpBasic();
     * 
     * return http.build();
     * }
     */

    /*
     * @Bean
     * public UserDetailsService userDetailsService(PasswordEncoder encoder) {
     * 
     * UserDetails admin = User.withUsername("toto")
     * .password(encoder.encode("pdw"))
     * .roles("ADMIN")
     * .build();
     * 
     * UserDetails user = User.withUsername("toto2")
     * .password(encoder.encode("pdw2"))
     * .roles("USER")
     * .build();
     * 
     * return new InMemoryUserDetailsManager(admin, user);
     * }
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests().anyRequest().permitAll()
                .and()
                //.addFilter(new CustomAuthenticationFilter(new AuthenticationManager(authenticationManagerBean())))
                // .authorizeHttpRequests((authorize)->
                // authorize.requestMatchers("/api/users").permitAll())//anyRequest().authenticated())//.authenticated())

                // .requestMatchers("/api/user/save").permitAll().and()
                // .authorizeHttpRequests().requestMatchers("/api/users")
                // .authenticated().and().formLogin()
                // .and()
                .build();

    }

    

}
