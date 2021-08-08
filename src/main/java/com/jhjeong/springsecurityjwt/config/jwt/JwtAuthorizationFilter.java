package com.jhjeong.springsecurityjwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jhjeong.springsecurityjwt.config.auth.PrincipalDetails;
import com.jhjeong.springsecurityjwt.model.User;
import com.jhjeong.springsecurityjwt.repository.UserRepository;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// BasicAuthenticationFilter - 권한이나 인증이 필요한 경우 해당 필터를 거침
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

  private UserRepository userRepository;

  public JwtAuthorizationFilter(
      AuthenticationManager authenticationManager, UserRepository userRepository) {
    super(authenticationManager);
    this.userRepository = userRepository;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {

    // JWT 검증
    String jwtHeader = request.getHeader("Authorization");
    if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
      chain.doFilter(request, response);
      return;
    }

    String jwtToken = jwtHeader.replace("Bearer ", "");
    String username = JWT.require(Algorithm.HMAC512("MY_SECRET")).build().verify(jwtToken)
        .getClaim("username").asString();

    if (username != null) {
      User userEntity = userRepository.findByUsername(username);
      PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
      Authentication authentication =
          new UsernamePasswordAuthenticationToken(principalDetails, null,
              principalDetails.getAuthorities());

      // 강제로 시큐리티 세션에 접근해서 Authentication 객체 저장
      SecurityContextHolder.getContext().setAuthentication(authentication);

      chain.doFilter(request, response);
    }
  }
}
