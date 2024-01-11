package com.mysite.pch.JWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

/*
Jwt Token 방식을 사용할 때 필요한 기능들을 정리해놓은 클래스
새로운 Jwt Token 발급, Jwt Token의 Claim에서 "loginId" 꺼내기, 만료 시간 체크 기능 수행
 */
public class JwtTokenUtil {

    // JWT Token 발급
    public static String createToken(String loginId, String key, long expireTimeMs) {
        // Claim = Jwt Token에 들어갈 정보
        // Claim에 loginId를 넣어 줌으로써 나중에 loginId를 꺼낼 수 있음
        Claims claims = Jwts.claims();
        claims.put("loginId", loginId);

        return Jwts.builder()
                .setClaims(claims)  // 발급할 토큰에 클레임 정보 설정
                .setIssuedAt(new Date(System.currentTimeMillis()))  // 토큰 발급 시간 설정
                .setExpiration(new Date(System.currentTimeMillis() + expireTimeMs))  // 토큰 만료 시간 설정
                .signWith(SignatureAlgorithm.HS256, key)  // 토큰에 서명 알고리즘과 서명할 키 설정
                .compact();  // 토큰 생성
    }

    // Claims에서 loginId 꺼내기
    public static String getLoginId(String token, String secretKey) {
        return extractClaims(token, secretKey).get("loginId").toString();
    }

    // 밝급된 Token이 만료 시간이 지났는지 체크
    public static boolean isExpired(String token, String secretKey) {
        Date expiredDate = extractClaims(token, secretKey).getExpiration();
        // Token의 만료 날짜가 지금보다 이전인지 check
        return expiredDate.before(new Date());
    }

    // SecretKey를 사용해 Token Parsing
    private static Claims extractClaims(String token, String secretKey) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }
}