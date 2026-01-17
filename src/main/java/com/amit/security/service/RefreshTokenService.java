package com.amit.security.service;

import com.amit.security.dto.response.LoginResponse;
import com.amit.security.entity.User;

public interface RefreshTokenService {

    void saveToken(String refresh_token, User user);

    LoginResponse generateAccessTokenAndRotateRefreshToken(String refreshToken);
}
