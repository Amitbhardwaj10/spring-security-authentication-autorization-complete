package com.amit.security.controller;

import com.amit.security.entity.User;
import com.amit.security.repository.UserRepository;
import com.amit.security.service.TokenBlocklistService;
import com.amit.security.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final UserRepository userRepository;

    private final UserService userService;

    private final TokenBlocklistService tokenBlocklistService;

    public UserController(UserRepository userRepository, UserService userService, TokenBlocklistService tokenBlocklistService) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.tokenBlocklistService = tokenBlocklistService;
    }

    @PostMapping("/register")
    public User register(@RequestBody User user) {
        return userService.register(user);
    }

    @PostMapping("/login")
    public String login(@RequestBody User user) {
       return userService.verify(user);
    }

    @PostMapping("/logout")
    public String logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
            String jwt = authHeader.substring(7);
            tokenBlocklistService.blocklistToken(jwt);
        }
        return "Logged out successfully";
    }
}
