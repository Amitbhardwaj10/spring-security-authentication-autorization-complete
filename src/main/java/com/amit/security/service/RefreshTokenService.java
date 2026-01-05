package com.amit.security.service;

import com.amit.security.entity.User;

public interface RefreshTokenService {

    void saveToken(String refresh_token, User user);

    String generateAccessTokenFromRefreshToken(String refreshToken);
}
