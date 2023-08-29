package com.ari.authentication.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "9fe8823a2577a2754cf9a1aedf044ca9dfad90bba52536403c954b1157f5ebf746bf31db57bcb741cfc430feec238946f7daf7833b351c8d3ac82d92a3cbffb607ea01f06e8d7e635895966b5e4b1c378dd0d248aa6bd55bbad15cb74cc03283e2ab3c9ac14be4897e87552721bdc708ce456d24236392cd41d7569211226ea45e61e9261bd62c4ab039a0c522ac440c314e7023d470b7e7f919a5104194ee918d8ec3ef04720e4fa79072b5d85e3da9225d632ecdf90cd9050e293bce80351d28b1141371bf4a0f0485b4c66d27c0033157ce0052f9d6eed051221db63e4bd7a9514d1dae941042706f4722ca6a69a466bace1e3e12c4e03bb443dcb75af0cf";

    public String extractUsername(String jwt){
        return  extractClaims(jwt, Claims::getSubject);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        System.out.println("========== User Details " + userDetails);
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSigningKey())
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    private Key getSigningKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
