package com.niit.walmart.service;

import com.niit.walmart.model.User;
import com.niit.walmart.repo.UserRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JWTUserDetailService implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(JWTUserDetailService.class);

    @Autowired
    private UserRepo repo;

    @Autowired
    private PasswordEncoder bcryptEncoder;

    @Override
    @Cacheable(value = "users", key = "#username")
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.debug("Loading user details for username: {}", username);
        User user = repo.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("User not found with the username of: " + username);
        }

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                new ArrayList<>());
    }

    @CacheEvict(value = "users", key = "#user.username")
    public User save(User user) {
        User newUser = new User(user.getUsername(), bcryptEncoder.encode(user.getPassword()), user.getEmail(),
                user.getName(), user.getAddress(), user.getPhone());

        return repo.save(newUser);
    }
}
