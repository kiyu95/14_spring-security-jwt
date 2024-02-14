package com.ohgiraffers.security.auth.service;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.user.service.UserService;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class DetailsService implements UserDetailsService { // AuthenticationProvider에서 검증 할 때 호출된다

    private final UserService userService;

    public DetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 유효성 검사를 진행함
        if (username == null || username.equals("")) {
            throw new AuthenticationServiceException(username + " is Empty");
        }

        // DB에서 username에 해당하는 정보를 꺼내온다

        return userService.findUser(username)
                .map(data -> new DetailsUser(Optional.of(data))) // 오류가 발생하지 않으면 정상적으로 진행
                .orElseThrow(() -> new AuthenticationServiceException(username)); // 오류가 발생하면 excoption 날림
    }
}
