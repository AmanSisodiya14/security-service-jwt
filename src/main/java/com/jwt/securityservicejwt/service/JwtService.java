package com.jwt.securityservicejwt.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.securityservicejwt.security.EncryptionService;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


@Service
@Slf4j
public class JwtService implements IJwtService {
    @Autowired
    private  ObjectMapper objectMapper;

    @Value("${jwt.token.expiration-time}")
    private long TOKEN_EXPIRATION_TIME;

    @Value("${jwt.token.refresh-token-expiration-time}")
    private long REFRESH_TOKEN_EXPIRATION_TIME;

    @Value("${jwt.key}")
    private String SECRET;

    @Autowired
    private EncryptionService encryptionService;


    @Override
    public String generateAccessToken(String userPayload) throws Exception {
        log.info("started generating access token");

        JsonNode jsonNode = objectMapper.readTree(userPayload);
        Map<String, Object> claims = getClaims(jsonNode);
        log.info("completed generating access token");

        return generateToken(claims, TOKEN_EXPIRATION_TIME);
    }

    @Override
    public String generateRefreshToken(String userPayload) throws Exception {
        log.info("started generating refresh token");
        JsonNode jsonNode = objectMapper.readTree(userPayload);

        Map<String, Object> claims = getClaims(jsonNode);
        log.info("completed generating refresh token");

        return generateToken(claims, REFRESH_TOKEN_EXPIRATION_TIME);
    }

    private String generateToken(Map<String, Object> claims, Long expiration) throws Exception {
        log.info("started generating token");
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonData = objectMapper.writeValueAsString(claims);
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("claims", encryptionService.encrypt(jsonData));

        log.info("completed generating token");
        return Jwts.builder()
                .setClaims(claimsMap)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
    }

    @Override
    public String generateAccessToken(Map<String, Object> claims) throws Exception {
        return generateToken(claims, TOKEN_EXPIRATION_TIME);
    }

    @Override
    public String generateRefreshToken(Map<String, Object> claims) throws Exception {
        return generateToken(claims, REFRESH_TOKEN_EXPIRATION_TIME);
    }

    @Override
    public void canTokenBeRefreshed(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(SECRET).build().parseClaimsJws(token);
        } catch (ExpiredJwtException e) {
            log.error("JWT expired: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "refreshToken_expired");
        }
    }

    @Override
    public Map<String, Object> validateToken(String token, HttpServletRequest request) {


        try {
            String origin = request.getHeader("origin");
            URI uri = new URI(origin);
            String host = uri.getHost();
            String subdomain = host.split("\\.")[0];
            Jwts.parserBuilder().setSigningKey(SECRET).build().parseClaimsJws(token);
            Claims claims = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token)
                    .getBody();
            String decryptedJson = encryptionService.decrypt((String) claims.get("claims"));
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> claimsMap = objectMapper.readValue(decryptedJson, new TypeReference<Map<String, Object>>() {
            });
            Object userDomain = claimsMap.get("domain");
            if(!Objects.equals(userDomain,subdomain) ){
                if(Objects.equals(subdomain,"iot") && userDomain == null){
                    return claimsMap;
                }
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "domain_invalid");
            }
            return claimsMap;
        } catch (ExpiredJwtException e) {
            log.error("JWT expired: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "token_expired");
        } catch (JwtException | IllegalArgumentException e) {
            log.error("Invalid JWT: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "token_invalid");
        } catch (Exception e) {
            log.error("Exception : {}", e.getMessage());
            throw new RuntimeException(e);
        }


    }


    private static Map<String, Object> getClaims(JsonNode jsonNode) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("customerType", jsonNode.path("customerType").path("customerType"));
        claims.put("customerId", jsonNode.path("customer").path("customerId"));
        claims.put("fleetId", jsonNode.path("fleet").path("fleetId"));
        claims.put("phoneNumber", jsonNode.path("phoneNumber"));
        claims.put("roleId", jsonNode.path("roleId"));
        claims.put("userId", jsonNode.path("userId"));
        claims.put("email", jsonNode.path("email"));
        claims.put("industryId", jsonNode.path("tenant").path("industry").path("id"));
        claims.put("tenantId", jsonNode.path("tenant").path("tenantId"));
        claims.put("domain", jsonNode.path("tenant").path("domainName"));

        return claims;
    }

}
