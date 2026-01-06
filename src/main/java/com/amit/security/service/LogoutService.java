package com.amit.security.service;

import com.amit.security.repository.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.util.WebUtils;

import java.util.Arrays;
import java.util.List;

@Service
public class LogoutService implements LogoutHandler {

    private final RefreshTokenRepository refreshTokenRepository;

    public LogoutService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        Cookie cookie = WebUtils.getCookie(request, "refresh_token");
        String refreshJwt = (cookie != null) ? cookie.getValue() : null;

        if (refreshJwt == null) return;

        var rt = refreshTokenRepository.findByToken(refreshJwt).orElse(null);

        if (rt != null) {
            refreshTokenRepository.delete(rt);
        }
    }
}
