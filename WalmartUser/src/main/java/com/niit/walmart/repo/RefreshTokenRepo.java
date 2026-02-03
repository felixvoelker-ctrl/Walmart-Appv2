package com.niit.walmart.repo;

import com.niit.walmart.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    
    Optional<RefreshToken> findByUsername(String username);
    
    @Modifying
    void deleteByUsername(String username);
    
    @Modifying
    void deleteByToken(String token);
}
