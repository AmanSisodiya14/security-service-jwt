package com.jwt.securityservicejwt.service;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

public interface IJwtService {
    String generateRefreshToken(String employeeProfilePayload) throws Exception;

    String generateAccessToken(String employeeProfilePayload) throws Exception;

    Map<String, Object> validateToken(String token, HttpServletRequest request) throws Exception;

    String generateAccessToken(Map<String, Object> claims) throws Exception;

    String generateRefreshToken(Map<String, Object> claims) throws Exception;

    void canTokenBeRefreshed(String token);

}
