package com.jhjeong.springsecurityjwt.config;

import com.jhjeong.springsecurityjwt.config.jwt.JwtAuthenticationFilter;
import com.jhjeong.springsecurityjwt.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final CorsFilter corsFilter;

  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .addFilter(corsFilter) // @CrossOrigin: 인증이 없을 때, 인증이 있을 때는 필터에 등록
        .formLogin().disable() // 기본 로그인 경로 비활성화
        .httpBasic().disable()
        .addFilter(new JwtAuthenticationFilter(authenticationManager()))
        .authorizeRequests()
        .antMatchers("/api/v1/user/**")
        .hasAnyRole(Role.USER.name(), Role.MANAGER.name(), Role.ADMIN.name())
        .antMatchers("/api/v1/manager/**")
        .hasAnyRole(Role.MANAGER.name(), Role.ADMIN.name())
        .antMatchers("/api/v1/admin/**")
        .hasRole(Role.ADMIN.name())
        .anyRequest().permitAll();
  }
}
