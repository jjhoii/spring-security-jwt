package com.jhjeong.springsecurityjwt.config.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// /login 요청, username, password 전송 시 동작
// 현재 기본 동작을 비활성화 했기 때문에 동작하지 안흥ㅁ
// 동작하게 하기 위해 필터 등록 필요
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;

  // /login 요청을 하면 로그인 시도를 위해 실행되는 함수
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {

    // 1. authenticationManager로 로그인 시도
    // 2. PrincipalDetailsService의 loadUserByUsername() 실행
    // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해)
    // 4. JWT 토큰을 만들어서 응답

    return super.attemptAuthentication(request, response);
  }
}
