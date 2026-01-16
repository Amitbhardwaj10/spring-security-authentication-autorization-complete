package com.amit.security.controller;

import com.amit.security.dto.request.LoginRequest;
import com.amit.security.dto.response.LoginResponse;
import com.amit.security.entity.User;
import com.amit.security.repository.RefreshTokenRepository;
import com.amit.security.repository.UserRepository;
import com.amit.security.service.RefreshTokenService;
import com.amit.security.service.UserService;
import com.amit.security.service.UserServiceImpl;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.*;
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
    public ResponseEntity<?> generateAccessTokenViaRefreshToken(@CookieValue(value = "refresh_token", required = false) String refreshTokenFromCookie) {
        if (refreshTokenFromCookie.isBlank())
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("missing refresh token!");

        String accessToken = refreshTokenService.generateAccessTokenFromRefreshToken(refreshTokenFromCookie);
        return ResponseEntity.ok(LoginResponse.builder().access_token(accessToken).build());
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @CookieValue(value = "refresh_token", required = false) String refreshToken,
            HttpServletResponse response
    ) {
        userService.logout(refreshToken, response);

        return ResponseEntity.ok(
                Map.of("message", "Logout successfully"));

    }
}
