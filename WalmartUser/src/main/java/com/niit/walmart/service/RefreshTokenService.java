package com.niit.walmart.service;

import com.niit.walmart.Exception.TokenRefreshException;
import com.niit.walmart.model.RefreshToken;
import com.niit.walmart.repo.RefreshTokenRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    
    @Value("${jwt.refresh.expiration:604800}")
    private Long refreshTokenDurationSeconds;

    @Autowired
    private RefreshTokenRepo refreshTokenRepo;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepo.findByToken(token);
    }

    public RefreshToken createRefreshToken(String username) {
        Optional<RefreshToken> existingToken = refreshTokenRepo.findByUsername(username);
        existingToken.ifPresent(token -> refreshTokenRepo.delete(token));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUsername(username);
        refreshToken.setExpiryDate(Instant.now().plusSeconds(refreshTokenDurationSeconds));
        refreshToken.setToken(UUID.randomUUID().toString());

        return refreshTokenRepo.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isExpired()) {
            refreshTokenRepo.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token has expired. Please login again.");
        }
        return token;
    }

    @Transactional
    public void deleteByUsername(String username) {
        refreshTokenRepo.deleteByUsername(username);
    }

    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepo.deleteByToken(token);
    }
}
