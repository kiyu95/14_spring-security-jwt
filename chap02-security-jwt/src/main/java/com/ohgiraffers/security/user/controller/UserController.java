package com.ohgiraffers.security.user.controller;

import com.ohgiraffers.security.user.entity.User;
import com.ohgiraffers.security.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity signup(@RequestBody User user){

        User signup = userService.signup(user);
        if (Objects.isNull(signup)){
            return ResponseEntity.status(500).body("가입 실패");
        }
        return ResponseEntity.ok(signup);
    }
}
