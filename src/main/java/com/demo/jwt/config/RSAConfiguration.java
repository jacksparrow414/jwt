package com.demo.jwt.config;

import com.demo.jwt.util.PEMKeyUtils;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

/**
 * https://connect2id.com/products/nimbus-jose-jwt/examples/pem-encoded-objects
 */
@Configuration
@Component
public class RSAConfiguration {

    @Bean(name = "RsaSigner")
    @SneakyThrows
    public JWSSigner generateJwsSigner(){
        String pemEncodedRSAPrivateKey = PEMKeyUtils.readKeyAsString("rsa/private-key.pem");
        RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects(pemEncodedRSAPrivateKey);
        return new RSASSASigner(rsaKey.toRSAPrivateKey());
    }

    @Bean(name = "RsaVerifier")
    @SneakyThrows
    public JWSVerifier getJWSVerifier() {
        String pemEncodedRSAPublicKey = PEMKeyUtils.readKeyAsString("rsa/publish-key.pem");
        RSAKey rsaPublicKey = (RSAKey) JWK.parseFromPEMEncodedObjects(pemEncodedRSAPublicKey);
        return new RSASSAVerifier(rsaPublicKey);
    }
}
