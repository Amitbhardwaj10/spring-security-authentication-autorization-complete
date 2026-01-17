package com.amit.security.utils;

import org.springframework.http.ResponseCookie;

public class CookieUtil {
    public static ResponseCookie deleteRefreshTokenCookie() {
        return ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(false)
                .path("/api/v1/auth")
                .maxAge(0)
                .build();
    }
}
