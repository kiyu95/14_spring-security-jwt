package com.ohgiraffers.security.auth.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class HeaderFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletResponse res = (HttpServletResponse) response;
        res.setHeader("Access-Control-Allow-Origin", "*"); // 외부에서 요청을 허용 등록
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"); // 어떤 요청을 허용할지 등록
        res.setHeader("Access-Control-Max-Age", "3600"); // 얼마나 허용할 것인가
        res.setHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Types Authorization, X-XSRF-token"); // 서버가 클라이언트 요청에 대해 허용하는 헤더를 설정
        res.setHeader("Access-Control-Allow-Credentials", "false"); // 서버는 요청에 대해 인증 정보를 포함하지 않도록 설정
        chain.doFilter(request, response);
    }
}
