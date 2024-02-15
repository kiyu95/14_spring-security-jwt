package com.ohgiraffers.security.auth.handler;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private DetailsService detailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException { // UserDetail과 입력값을 비교하는 로직
        // 1. username password Token(사용자가 로그인 요청시 날린 아이디와 비밀번호를 가지고 있는 임시 객체)
        UsernamePasswordAuthenticationToken loginToken = (UsernamePasswordAuthenticationToken) authentication;
        String username = loginToken.getName(); // 토큰에서 사용자가 입력한 아이디
        String password = (String) loginToken.getCredentials(); // 사용자가 입력한 비밀번호, getCredentials() : 토근이 가지고 있는 값

        // 2. DB에서 username에 해당하는 정보를 조회한다.
        DetailsUser foundUser = (DetailsUser) detailsService.loadUserByUsername(username);

        // 사용자가 입력한 username, password와 아이디의 비밀번호와 비교하는 로직을 수행함
        if (!passwordEncoder.matches(password, foundUser.getPassword())){ // password : 입력값, foundUser.getPassword() 인코딩 된 값
            throw new BadCredentialsException(password +"가 " + username + "의 password가 일치하지 않습니다.");
        }

        return new UsernamePasswordAuthenticationToken(foundUser, password, foundUser.getAuthorities()); // foundUser : 사용자 정보, password : 비밀번호, foundUser.getAuthorities() : 권한 목록
    }

    @Override
    public boolean supports(Class<?> authentication) {

        return authentication.equals(UsernamePasswordAuthenticationToken.class); // authentication 와 UsernamePasswordAuthenticationToken.class 가 같은지 비교. 같으면 true(성공), 다르면 false(실패)
    }
}
