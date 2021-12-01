package com.demo.jwt.controller;

import com.demo.jwt.util.PEMKeyUtils;
import com.demo.jwt.vo.Token;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import lombok.SneakyThrows;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Calendar;

import java.util.Date;
import java.util.UUID;

@RestController
@RequestMapping("generate")
@Log
public class GenerateTokenController {

    @Autowired
    private JWSSigner signer;

    /**
     * https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
     *
     * curl http://localhost:18080/jwt/generate/111
     * @param userId
     * @return
     */
    @GetMapping("{userId}")
    @SneakyThrows
    public String generateToken(@PathVariable String userId) {
        Calendar signTime = Calendar.getInstance();
        Date signTimeTime = signTime.getTime();
        signTime.add(Calendar.MINUTE, 10);
        Date expireTime = signTime.getTime();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("http://localhost:18080")
                .subject(userId)
                .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                .expirationTime(expireTime)
                .notBeforeTime(signTimeTime)
                .issueTime(signTimeTime)
                .jwtID(UUID.randomUUID().toString())
                .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(), claimsSet);
        signedJWT.sign(signer);
        String result = signedJWT.serialize();
        log.info("token is: \n" + result);
        return result;
    }
}
