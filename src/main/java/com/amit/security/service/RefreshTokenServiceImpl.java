package com.amit.security.service;

import com.amit.security.entity.RefreshToken;
import com.amit.security.entity.User;
import com.amit.security.repository.RefreshTokenRepository;
import com.amit.security.repository.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Date;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    private final JwtService jwtService;

    private final UserRepository userRepository;

    public RefreshTokenServiceImpl(RefreshTokenRepository refreshTokenRepository, JwtService jwtService, UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
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

    @Override
    public String generateAccessTokenFromRefreshToken(String refreshTokenFromCookie) {

        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenFromCookie).orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // check expiry from DB
        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Refresh token expired");
        }

        // validate JWT integrity (signature + expiration claim)
        if (!jwtService.isRefreshTokenValid(refreshTokenFromCookie)) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Invalid refresh token");
        }

        // generate access token
        var user = refreshToken.getUser();
        return jwtService.generateAccessToken(user);
    }
}
