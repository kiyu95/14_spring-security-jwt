package com.ohgiraffers.security.auth.filter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ohgiraffers.security.auth.model.dto.LoginDTO;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        super.setAuthenticationManager(authenticationManager);
    }

    // 지정된 url 요청시 해당 요청을 가로채서 검증 로직을 수행하는 메서드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        UsernamePasswordAuthenticationToken authenticationToken;

        try {
            authenticationToken = getAuthRequest(request);
            setDetails(request, authenticationToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return this.getAuthenticationManager().authenticate(authenticationToken);
    }

    /**
     * 사용자의 로그인 리소스 요청시 요청 정보를 임시 토큰에 저장하는 메서드
     *
     * @Param request = httpServletRequest
     * @return UserPasswordAuthenticationToken
     * @throw Exception e
     * */
    private UsernamePasswordAuthenticationToken getAuthRequest(HttpServletRequest request) throws IOException {

        ObjectMapper objectMapper = new ObjectMapper();

        objectMapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true);
        LoginDTO user = objectMapper.readValue(request.getInputStream(), LoginDTO.class);

        return new UsernamePasswordAuthenticationToken(user.getId(), user.getPass());
    }
}
