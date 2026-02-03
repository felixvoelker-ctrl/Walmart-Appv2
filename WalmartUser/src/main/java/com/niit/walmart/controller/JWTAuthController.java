package com.niit.walmart.controller;

import com.niit.walmart.config.JWTUtil;
import com.niit.walmart.Exception.InvalidCredentialsException;
import com.niit.walmart.Exception.TokenRefreshException;
import com.niit.walmart.Exception.UserDisabledException;
import com.niit.walmart.model.RefreshToken;
import com.niit.walmart.model.User;
import com.niit.walmart.repo.UserRepo;
import com.niit.walmart.service.JWTUserDetailService;
import com.niit.walmart.service.RefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/auth")
public class JWTAuthController {
    private static final Logger logger = LoggerFactory.getLogger(JWTAuthController.class);

    @Autowired
    private UserRepo repo;

    @Autowired
    private JWTUserDetailService jwtUserDetailsService;

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @CrossOrigin
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public ResponseEntity<User> getCurrentUser (HttpServletRequest request)  {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User user = repo.findByUsername(((UserDetails) principal).getUsername());
        return ResponseEntity.ok(user);
    }

    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity<?> registerUser (@RequestBody Map<String, Object> user) throws Exception {
        User savedUser = new User();
        User newUser = new User(
                (String) user.get("username"),
                (String) user.get("password"),
                (String) user.get("email"),
                (String) user.get("name"),
                (String) user.get("address"),
                (String) user.get("phone")
        );

        if (newUser.getUsername() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username is missing.");
        }

        if (newUser.getEmail() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email is missing.");
        }

        if (newUser.getPassword() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Password is missing.");
        } else if (newUser.getPassword().length() < 8) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Password length must be 8+.");
        }

        if (newUser.getName() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Name is missing.");
        }

        if (newUser.getAddress() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Address is missing.");
        }

        if (newUser.getPhone() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Phone is missing.");
        }

        try {
            savedUser = jwtUserDetailsService.save(newUser);
        } catch (DataIntegrityViolationException e) {
            if (e.getRootCause().getMessage().contains(newUser.getUsername())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username is not available.");
            }

            if (e.getRootCause().getMessage().contains(newUser.getEmail())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email is not available.");
            }
        }

        Map<String, Object> tokenResponse = new HashMap<>();

        final UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(savedUser.getUsername());
        final String token = jwtUtil.generateToken(userDetails);

        tokenResponse.put("token", token);
        return ResponseEntity.status(HttpStatus.CREATED).body(tokenResponse);
    }

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<?> authenticateUser (@RequestBody Map<String, String> user) {
        authenticate(user.get("username"), user.get("password"));

        Map<String, Object> tokenResponse = new HashMap<>();
        final UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(user.get("username"));
        final String accessToken = jwtUtil.generateToken(userDetails);
        final RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.get("username"));

        tokenResponse.put("token", accessToken);
        tokenResponse.put("refreshToken", refreshToken.getToken());
        logger.info("User {} logged in successfully", user.get("username"));
        return ResponseEntity.ok(tokenResponse);
    }

    @RequestMapping(value = "/refresh-token", method = RequestMethod.POST)
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String requestRefreshToken = request.get("refreshToken");

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUsername)
                .map(username -> {
                    UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);
                    String newAccessToken = jwtUtil.generateToken(userDetails);

                    Map<String, Object> tokenResponse = new HashMap<>();
                    tokenResponse.put("token", newAccessToken);
                    tokenResponse.put("refreshToken", requestRefreshToken);
                    logger.debug("Token refreshed for user {}", username);
                    return ResponseEntity.ok(tokenResponse);
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token not found"));
    }

    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public ResponseEntity<?> logoutUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            String username = ((UserDetails) principal).getUsername();
            refreshTokenService.deleteByUsername(username);
            logger.info("User {} logged out successfully", username);
        }
        return ResponseEntity.ok().body("Logged out successfully");
    }

    private void authenticate(String username, String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new UserDisabledException();
        } catch (BadCredentialsException e) {
            throw new InvalidCredentialsException();
        }
    }
}
