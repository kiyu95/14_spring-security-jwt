package com.ohgiraffers.security.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

public class CustomAuthFailureHandler implements AuthenticationFailureHandler {

    /*
    * onAuthenticationFailure 메소드가 호출될 defaultFailureUrl인 경우 리다이렉션을 수행하는 AuthenticationFailUreHandle.
    * 속성이 설정되어 있지 않는 경우 실패를 일으킨 AuthenticationException의 오류 메세지와 함께 클라이언트에게 401 오류를 응답한다.
    * */

    /**
     * 사용자의 잘못된 로그인 시도를 커스텀 하기 위한 핸들러이다.
     * @param request 사용자 요청 객체
     * @param response 서버 응답값
     * @param exception 발생한 오류를 담는 객체
     * */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        JSONObject jsonObject;
        String failMsg;

        if (exception instanceof AuthenticationServiceException){
            failMsg = "존재하지 않는 사용자 입니다.";
        } else if (exception instanceof LockedException) {
            failMsg = "잠긴 계정입니다.";
        } else if (exception instanceof DisabledException) {
            failMsg = "비활성화된 계정입니다.";
        } else if (exception instanceof AccountExpiredException) {
            failMsg = "만류된 계정입니다.";
        } else if (exception instanceof CredentialsExpiredException) {
            failMsg = "자격 증명이 만료된 계정입니다.";
        } else if (exception instanceof AuthenticationCredentialsNotFoundException) {
            failMsg = "인증 요청이 거부되었습니다.";
        } else if (exception instanceof UsernameNotFoundException) {
            failMsg = "존재하지 않는 이메일 입니다.";
        } else {
            failMsg = "정의 되어있지 않는 오류 케이스 입니다.";
        }

        response.setContentType("application/json");
        request.setCharacterEncoding("UTF-8");
        PrintWriter printWriter = response.getWriter();

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("failType", failMsg);

        jsonObject = new JSONObject(resultMap);

        printWriter.println(jsonObject);
        printWriter.flush();
        printWriter.close();
    }
}
