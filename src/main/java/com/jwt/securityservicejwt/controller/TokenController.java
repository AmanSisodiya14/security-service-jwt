package com.jwt.securityservicejwt.controller;

import com.jwt.securityservicejwt.entity.IotResponse;
import com.jwt.securityservicejwt.entity.JwtResponse;
import com.jwt.securityservicejwt.service.IJwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/authservice")
@Slf4j
public class TokenController {

    @Autowired
    private IJwtService jwtService;

    @PostMapping("/v1/auth/jwt")
    public ResponseEntity<?> login(@RequestBody String userPayload) {
        try {
            String token = this.jwtService.generateAccessToken(userPayload);

            String refreshToken = this.jwtService.generateRefreshToken(userPayload);

            JwtResponse response = JwtResponse.builder().accessToken(token).refreshToken(refreshToken).tokenType("Bearer").build();
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/v1/auth/jwt/validate")
    public ResponseEntity<?> validateToken(HttpServletRequest request) throws Exception {
        log.info("Received JWT validation request");
        String requestHeader = request.getHeader("Authorization");
        if (requestHeader != null && requestHeader.startsWith("Bearer ")) {
            String token = requestHeader.substring(7);
            // Validate the token and retrieve claims map
            Map<String, Object> claimsMap = jwtService.validateToken(token, request);
            // Create headers
            HttpHeaders headers = new HttpHeaders();
            // set claims in response header
            claimsMap.forEach((key, value) -> headers.add(key, String.valueOf(value)));

            // Return response with headers
            log.info("Token validated successfully.");
            return ResponseEntity.ok()
                    .headers(headers)
                    .body("Token validated successfully.");
        }
        log.info("Token not found");
        return new ResponseEntity<>(new IotResponse<>("Token not found",
                HttpStatus.UNAUTHORIZED.value(), false), HttpStatus.UNAUTHORIZED);
    }

    @GetMapping("/v1/auth/jwt/refresh/token")
    public ResponseEntity<Object> refreshToken(HttpServletRequest request) {
        try {
            String requestHeader = request.getHeader("Authorization");
            if (requestHeader != null && requestHeader.startsWith("Bearer ")) {
                String refreshToken = requestHeader.substring(7);
                jwtService.canTokenBeRefreshed(refreshToken);
                Map<String, Object> claims = jwtService.validateToken(refreshToken, request);

                String newToken = this.jwtService.generateAccessToken(claims);

                JwtResponse response = JwtResponse.builder().accessToken(newToken)
                        .tokenType("Bearer")
                        .build();
                return new ResponseEntity<>(response, HttpStatus.OK);
            } else {
                return new ResponseEntity<>("Invalid Refresh token", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (Exception e) {
            log.info( "error while generate access token using refresh token : :"+ e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


}
