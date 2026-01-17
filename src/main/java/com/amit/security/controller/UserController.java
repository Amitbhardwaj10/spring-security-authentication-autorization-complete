package com.amit.security.controller;

import com.amit.security.dto.request.LoginRequest;
import com.amit.security.dto.response.LoginResponse;
import com.amit.security.entity.User;
import com.amit.security.repository.RefreshTokenRepository;
import com.amit.security.repository.UserRepository;
import com.amit.security.service.RefreshTokenService;
import com.amit.security.service.UserService;
import com.amit.security.service.UserServiceImpl;
import com.amit.security.utils.CookieUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class UserController {

    private final UserService userService;

    private final RefreshTokenService refreshTokenService;

    public UserController(UserRepository userRepository, UserServiceImpl userService, RefreshTokenService refreshTokenService, RefreshTokenRepository refreshTokenRepository) {
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public User register(@RequestBody User user) {
        return userService.register(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            LoginResponse result = userService.verify(loginRequest);

            ResponseCookie cookie = ResponseCookie.from("refresh_token", result.getRefresh_token())
                    .httpOnly(true)
                    .secure(true)
                    .path("/api/v1/auth")
                    .sameSite("Strict")
                    .maxAge(29 * 24 * 60 * 60)
                    .build();

            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(
                    LoginResponse.builder()
                            .access_token(result.getAccess_token())
                            .build());
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(e.getMessage());
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> generateAccessTokenViaRefreshToken(@CookieValue(value = "refresh_token", required = false) String refreshTokenFromCookie, HttpServletResponse response) {

        if (refreshTokenFromCookie == null)
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("refresh token is invalid or null");

        if (refreshTokenFromCookie.isBlank())
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("missing refresh token!");

        LoginResponse result = refreshTokenService.generateAccessTokenAndRotateRefreshToken(refreshTokenFromCookie);

        // Update the cookie
        ResponseCookie cookie = ResponseCookie.from("refresh_token", result.getRefresh_token())
                .httpOnly(true)
                .secure(true) // true in prod
                .path("/api/v1/auth")
                .maxAge(30L * 24 * 60 * 60)
                .sameSite("Strict")
                .build();


        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(
                        LoginResponse.builder()
                                .access_token(result.getAccess_token())
                                .build()
                );
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @CookieValue(value = "refresh_token", required = false) String refreshToken,
            HttpServletResponse response
    ) {
        userService.logout(refreshToken);

        ResponseCookie deleteCookie = CookieUtil.deleteRefreshTokenCookie();
        response.setHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

        return ResponseEntity.ok(
                Map.of("message", "Logout successfully"));
    }
}
