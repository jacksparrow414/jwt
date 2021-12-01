package com.demo.jwt.controller;

import com.demo.jwt.factory.JWTClaimsSetFactory;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("generate")
@Log
public class GenerateTokenController {

    @Autowired
    @Qualifier("RsaSigner")
    private JWSSigner rsaSigner;

    @Autowired
    @Qualifier("HmacSigner")
    private JWSSigner hmacSigner;

    @Autowired
    private JWTClaimsSetFactory jwtClaimsSetFactory;

    /**
     * https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
     *
     * curl http://localhost:18080/jwt/generate/111
     * @param userId
     * @return
     */
    @GetMapping("{userId}")
    @SneakyThrows
    public String generateRSAToken(@PathVariable String userId) {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(), jwtClaimsSetFactory.buildJWTClaimsSet(userId));
        signedJWT.sign(rsaSigner);
        String result = signedJWT.serialize();
        log.info("token is: \n" + result);
        return result;
    }

    @GetMapping("hmac")
    @SneakyThrows
    public String generateHMACToken() {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(), jwtClaimsSetFactory.buildJWTClaimsSet("ADMIN"));
        signedJWT.sign(hmacSigner);
        String result = signedJWT.serialize();
        log.info("HMAC token is: \n" + result);
        return result;
    }
}
