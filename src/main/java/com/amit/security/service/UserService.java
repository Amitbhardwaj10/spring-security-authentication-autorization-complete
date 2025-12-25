package com.amit.security.service;

import com.amit.security.entity.User;
import com.amit.security.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class UserService {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;

    public UserService(BCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepository, AuthenticationManager authenticationManager, JwtService jwtService) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public User register(User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public String verify(User user) {
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(), user.getPassword()
                )
        );

        if (authenticate.isAuthenticated()) {
            return jwtService.generateToken(user);
        }
        return "failure";
    }
}
