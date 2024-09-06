package org.sid.securityservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
// You will go to the properties file with the prefix "rsa" and inject the values
@ConfigurationProperties(prefix = "rsa")
public record RSAKeyConfig(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
}
