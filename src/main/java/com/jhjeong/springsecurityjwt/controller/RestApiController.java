package com.jhjeong.springsecurityjwt.controller;

import com.jhjeong.springsecurityjwt.model.Role;
import com.jhjeong.springsecurityjwt.model.User;
import com.jhjeong.springsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class RestApiController {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  @GetMapping
  public String home() {
    return "<h1>home</h1>";
  }

  @PostMapping("/join")
  public String josin(@RequestBody User user) {
    user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    user.setRoles(Role.USER.getKey());
    userRepository.save(user);
    return "success";
  }
}
