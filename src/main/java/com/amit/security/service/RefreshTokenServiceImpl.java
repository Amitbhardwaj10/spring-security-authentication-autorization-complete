package com.amit.security.service;

import com.amit.security.entity.RefreshToken;
import com.amit.security.entity.User;
import com.amit.security.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    private final JwtService jwtService;

    public RefreshTokenServiceImpl(RefreshTokenRepository refreshTokenRepository, JwtService jwtService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
    }

    @Override
    public void saveToken(String refresh_token, User user) {
        try {
            Instant tokenExpiration = jwtService.extractExpiration(refresh_token);

            RefreshToken refreshToken = RefreshToken.builder()
                    .token(refresh_token)
                    .user(user)
                    .expiryDate(tokenExpiration)
                    .build();

            refreshTokenRepository.save(refreshToken);
        } catch (Exception e) {
            throw new RuntimeException("Failed to save refresh token", e);
        }
    }
}
