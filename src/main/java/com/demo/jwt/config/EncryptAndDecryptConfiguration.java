package com.demo.jwt.config;

import com.demo.jwt.util.PEMKeyUtils;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

/**
 * @author jacksparrow414
 * @date 2021/12/1
 */
@Component
@Configuration
public class EncryptAndDecryptConfiguration {
    
    @Bean
    @SneakyThrows
    public JWEEncrypter generateRsaJweEncrypter() {
        String pemEncodedRSAPublicKey = PEMKeyUtils.readKeyAsString("rsa/publish-key.pem");
        RSAKey rsaPublicKey = (RSAKey) JWK.parseFromPEMEncodedObjects(pemEncodedRSAPublicKey);
        return new RSAEncrypter(rsaPublicKey);
    }
    
    @Bean
    @SneakyThrows
    public JWEDecrypter getRsaJweDecrypter() {
        String pemEncodedRSAPrivateKey = PEMKeyUtils.readKeyAsString("rsa/private-key.pem");
        RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects(pemEncodedRSAPrivateKey);
        return new RSADecrypter(rsaKey);
    }
}
