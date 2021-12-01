package com.demo.jwt.controller;

import com.demo.jwt.factory.JWTClaimsSetFactory;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.EncryptedJWT;
import lombok.SneakyThrows;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author jacksparrow414
 * @date 2021/12/1
 */
@RestController
@RequestMapping("secret")
@Log
public class SecretController {
    
    @Autowired
    private JWEEncrypter jweEncrypter;
    
    @Autowired
    private JWTClaimsSetFactory jwtClaimsSetFactory;
    
    @GetMapping("{userId}")
    @SneakyThrows
    public String secretToken(@PathVariable final String userId) {
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
        EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSetFactory.buildJWTClaimsSet(userId));
        encryptedJWT.encrypt(jweEncrypter);
        String result = encryptedJWT.serialize();
        log.info("encrypt token is: \n" + result);
        return result;
    }
}
