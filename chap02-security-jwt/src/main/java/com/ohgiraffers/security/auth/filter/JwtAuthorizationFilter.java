package com.ohgiraffers.security.auth.filter;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.common.AuthConstants;
import com.ohgiraffers.security.common.utils.TokenUtils;
import com.ohgiraffers.security.user.entity.User;
import com.ohgiraffers.security.user.model.OhgiraffersRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) { // 매니저 생성자로 만든 이유?
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        /* 권한이 필요없는 리소스 */
        List<String> roleLessList = Arrays.asList(
                "/signup"
        );

        // 권한이 필요 없는 요청이 들어왔는지 확인한다.
        if (roleLessList.contains(request.getRequestURI())){
            chain.doFilter(request, response); // request, response 체인으로 전달
            return; // 스코프를 여기서 끝내주기 위해 return; 사용
        }

        String header = request.getHeader(AuthConstants.AUTH_HEADER); // header에 담아 전달
//        System.out.println(header);

        try {
            // header가 존재하는 경우
            if (header != null && !header.equalsIgnoreCase("")){

                String token = TokenUtils.splitHeader(header); // 토큰 값만 가져옴

                if (TokenUtils.isValidToken(token)){ // 토큰 유효성 검사
                    Claims claims = TokenUtils.getClaimsFormToken(token); // 토큰을 복호화시켜 claims을 가져옴
                    DetailsUser authentication = new DetailsUser(); // DetailsUser 객체를 만들어줌, authenticationToken에 넣어주기 위해
                    User user = new User(); // DetailsUser에 유저 정보를 담기위해 User 엔티티 생성
                    user.setUserId(claims.get("userId").toString()); // clamis에서 꺼내온 필요한 정보만 담아준다

                    user.setRole(OhgiraffersRole.valueOf(claims.get("Role").toString()));
                    authentication.setUser(user); // 유저 정보를 넣어줌

                    AbstractAuthenticationToken authenticationToken =
                            UsernamePasswordAuthenticationToken.authenticated(authentication, token, authentication.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authenticationToken); // SecurityContextHolder에 넣어주는 이유? 인증 정보를 담아주기 위해?
                    chain.doFilter(request, response); // 다음로직 수행할 수 있게 처리
                } else {
                    throw new RuntimeException("토큰이 유효하지 않습니다.");
                }

            } else {
                throw new RuntimeException("토큰이 존재하지 않습니다.");
            }
        }
        catch (Exception e){
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter printWriter = response.getWriter();
            JSONObject jsonObject = jsonresponseWrapper(e);
            printWriter.println(jsonObject);
            printWriter.flush();
            printWriter.close();
        }
    }

    private JSONObject jsonresponseWrapper(Exception e){

        String resultMsg = "";
        if (e instanceof ExpiredJwtException){
            resultMsg = "Token Expired";
        } else if (e instanceof SignatureException){
            resultMsg = "Token SignatureException login";
        } else if (e instanceof JwtException){
            resultMsg = "Token parsing JwtException";
        } else {
            resultMsg = "Other Token Error";
        }

        HashMap<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("status", 401);
        jsonMap.put("message", resultMsg);
        jsonMap.put("reason", e.getMessage());
        JSONObject jsonObject = new JSONObject(jsonMap);
        return jsonObject;
    }

}
