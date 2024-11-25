package com.secure.notes.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

//register bean; keeps instance of class in application context; detect class for dependency injection
@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

//    Values will come from application.properties
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

//    Extracting jwt token from header
    public String getJwtFromHeader(HttpServletRequest request){
//        Extracting full token  as the format is:- Authorization : Bearer <token>
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}",bearerToken);
//        If bearerToken is not null and starts with bearer then get a substring of only token
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);  //Remove Bearer prefix(i.e Bearer and space)
        }
        return null;
    }

//    Creating token
    public String generateTokenFromUsername(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date().getTime() + jwtExpirationMs)))
                .signWith(key())
                .compact();
    }

    public String getUsernameFromJwtToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateJwtToken(String authToken){
        try{
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        }catch (MalformedJwtException e){
            logger.error("Invalid Jwt Token: {}",e.getMessage());
        }catch (ExpiredJwtException e){
            logger.error("Jwt Token is expired: {}",e.getMessage());
        }catch (IllegalArgumentException e){
            logger.error("Jwt claims string is empty: {}",e.getMessage());
        }
        return false;
    }
}
