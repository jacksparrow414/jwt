package com.demo.jwt.controller;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("verify")
public class VerifyTokenController {

    @Autowired
    private JWSVerifier verifier;

    /**
     * curl -H "Authorization: token" http://localhost:18080/jwt/verify
     * @param token
     * @return
     */
    @GetMapping
    @SneakyThrows
    public boolean verifyToken(@RequestHeader("Authorization") String token) {
        SignedJWT parse = SignedJWT.parse(token);
        return parse.verify(verifier);
    }
}
