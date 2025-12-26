package com.amit.security.service;

import com.amit.security.entity.Token;
import com.amit.security.repository.TokenRepository;
import org.springframework.stereotype.Service;

@Service
public class TokenBlocklistService {

    private final TokenRepository tokenRepository;

    public TokenBlocklistService(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    public void blocklistToken(String token) {
        tokenRepository.save(Token.builder().token(token).build());
    }

    public boolean isTokenBlocklisted(String token) {
        return tokenRepository.findByToken(token).isPresent();
    }
}
