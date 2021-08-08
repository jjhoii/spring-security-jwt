package com.jhjeong.springsecurityjwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jhjeong.springsecurityjwt.config.auth.PrincipalDetails;
import com.jhjeong.springsecurityjwt.model.User;
import java.io.IOException;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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

    try {
      // 1. username, password 받아옴
      ObjectMapper om = new ObjectMapper(); // json 파싱
      User user = om.readValue(request.getInputStream(), User.class);
      // 기본 동작을 비활성화 했기 때문에 토큰 직접 생성
      UsernamePasswordAuthenticationToken authenticationToken =
          new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

      // 2. authenticationManager로 로그인 시도
      // 3. PrincipalDetailsService의 loadUserByUsername() 실행
      // PrincipalDetailsService의 loadUserByUsername() 함수가 정상 실행되면 authentication 리턴 (로그인 성공)
      Authentication authentication = authenticationManager.authenticate(authenticationToken);

      // 4. PrincipalDetails를 세션에 담고 (권한 관리를 위해)
      // authentication 객체가 ssesion 영역에 저장
      return authentication;
    } catch (IOException e) {
      e.printStackTrace();
    }

    return null;
  }

  // attemptAuthentication 실행 후 인증시 정상적으로 진생되었다면 실행되는 메서드
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException, ServletException {
    // 5. JWT 토큰을 만들어서 응답

    PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

    String jwtToken = JWT.create()
        .withSubject(principalDetails.getUsername())
        .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
        .withClaim("id", principalDetails.getUser().getId())
        .withClaim("username", principalDetails.getUser().getUsername())
        .sign(Algorithm.HMAC512("MY_SECRET"));

    response.addHeader("Authorization", "Bearer " + jwtToken);

    //super.successfulAuthentication(request, response, chain, authResult);
  }
}
