package com.demo.jwt.controller;

import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Calendar;


@RestController
@RequestMapping("verify")
public class VerifyTokenController {

    @Autowired
    @Qualifier("RsaVerifier")
    private JWSVerifier rsaVerifier;

    @Autowired
    @Qualifier("HmacVerifier")
    private JWSVerifier hmacVerifier;
    
    @Autowired
    private JWEDecrypter jweDecrypter;

    /**
     * curl -H "Authorization: token" http://localhost:18080/jwt/verify
     * @param token
     * @return
     */
    @GetMapping
    @SneakyThrows
    public boolean verifyRSAToken(@RequestHeader("Authorization") String token) {
        SignedJWT parse = SignedJWT.parse(token);
        if (!parse.verify(rsaVerifier)) {
            throw new RuntimeException("invalid token");
        }
        verifyClaimsSet(parse.getJWTClaimsSet());
        return true;
    }

    @GetMapping("hmac")
    @SneakyThrows
    public boolean verifyHMACToken(@RequestHeader("Authorization") String token) {
        SignedJWT parse = SignedJWT.parse(token);
        if (!parse.verify(hmacVerifier)) {
            throw new RuntimeException("invalid token");
        }
        verifyClaimsSet(parse.getJWTClaimsSet());
        return true;
    }
    
    @GetMapping("decrypt")
    @SneakyThrows
    public void decryptRSASecretToken(@RequestHeader("Authorization") String token) {
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);
        encryptedJWT.decrypt(jweDecrypter);
    }

    /**
     * 所有验证在这里进行.
     * @param jwtClaimsSet
     */
    private void verifyClaimsSet(final JWTClaimsSet jwtClaimsSet) {
        boolean result = false;
        if (Calendar.getInstance().getTime().before(jwtClaimsSet.getExpirationTime())) {
            result = true;
        }
        if (!result) {
            throw new RuntimeException("token expired");
        }
    }
}
