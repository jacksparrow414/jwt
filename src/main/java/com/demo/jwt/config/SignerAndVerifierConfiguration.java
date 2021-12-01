package com.demo.jwt.config;

import com.demo.jwt.util.PEMKeyUtils;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

/**
 * https://connect2id.com/products/nimbus-jose-jwt/examples/pem-encoded-objects
 */
@Configuration
@Component
public class SignerAndVerifierConfiguration {

    private static final String sharedSecret = "31611159e7e6ff7843ea4627745e89225fc866621cfcfdbd40871af4413747cc";

    @Bean(name = "RsaSigner")
    @SneakyThrows
    public JWSSigner generateRsaJwsSigner(){
        String pemEncodedRSAPrivateKey = PEMKeyUtils.readKeyAsString("rsa/private-key.pem");
        RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects(pemEncodedRSAPrivateKey);
        return new RSASSASigner(rsaKey.toRSAPrivateKey());
    }

    @Bean(name = "RsaVerifier")
    @SneakyThrows
    public JWSVerifier getRsaJWSVerifier() {
        String pemEncodedRSAPublicKey = PEMKeyUtils.readKeyAsString("rsa/publish-key.pem");
        RSAKey rsaPublicKey = (RSAKey) JWK.parseFromPEMEncodedObjects(pemEncodedRSAPublicKey);
        return new RSASSAVerifier(rsaPublicKey);
    }

    /**
     * https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-hmac
     * @return
     */
    @Bean(name = "HmacSigner")
    @SneakyThrows
    public JWSSigner generateHmacJwsSigner() {
        SecureRandom random = new SecureRandom();
        random.nextBytes(sharedSecret.getBytes());
        return new MACSigner(sharedSecret);
    }

    @Bean(name = "HmacVerifier")
    @SneakyThrows
    public JWSVerifier getHmacJwsVerifier() {
        SecureRandom random = new SecureRandom();
        random.nextBytes(sharedSecret.getBytes());
        return new MACVerifier(sharedSecret);
    }
}
