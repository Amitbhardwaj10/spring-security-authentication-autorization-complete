package com.amit.security.service;

import com.amit.security.dto.request.LoginRequest;
import com.amit.security.dto.response.LoginResponse;
import com.amit.security.entity.User;
import jakarta.servlet.http.HttpServletResponse;

public interface UserService {
    User register(User user);
    LoginResponse verify(LoginRequest loginRequest);
    void logout(String refreshJwt);
}
