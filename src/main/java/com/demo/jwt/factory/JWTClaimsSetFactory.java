package com.demo.jwt.factory;

import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

@Component
public class JWTClaimsSetFactory {

    public JWTClaimsSet buildJWTClaimsSet(String userId) {
        Calendar signTime = Calendar.getInstance();
        Date signTimeTime = signTime.getTime();
        signTime.add(Calendar.MINUTE, 10);
        Date expireTime = signTime.getTime();
        return new JWTClaimsSet.Builder()
                .issuer("http://localhost:18080")
                .subject(userId)
                .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                .expirationTime(expireTime)
                .notBeforeTime(signTimeTime)
                .issueTime(signTimeTime)
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", "read write")
                .build();
    }
}
