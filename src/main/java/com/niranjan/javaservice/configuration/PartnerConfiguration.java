package com.niranjan.javaservice.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import javax.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Paths;

@Configuration
public class PartnerConfiguration {

    private String partnerPublicKey;
    private String privateKey;

    @PostConstruct
    public void init() throws Exception {
        // Load PEM files and extract keys
        partnerPublicKey = loadPublicKeyFromPem("keys/partner_public_key.pem");
        privateKey = loadPrivateKeyFromPem("keys/private_key.pem");
    }

    /**
     * Reads a PEM file and extracts the public key.
     *
     * @param pemFilePath the path to the PEM file
     * @return the string
     * @throws Exception if any error occurs during key reading
     */
    private String loadPublicKeyFromPem(String pemFilePath) throws Exception {
        Resource resource = new ClassPathResource(pemFilePath);
        String pemContent = new String(Files.readAllBytes(Paths.get(resource.getURI())));        
        String publicKeyPEM = pemContent.replace("-----BEGIN PUBLIC KEY-----", "")
                                       .replace("-----END PUBLIC KEY-----", "")
                                       .replaceAll("\\s", "");
        return publicKeyPEM;
    }

    /**
     * Reads a PEM file and extracts the private key.
     *
     * @param pemFilePath the path to the PEM file
     * @return the string
     * @throws Exception if any error occurs during key reading
     */
    private String loadPrivateKeyFromPem(String pemFilePath) throws Exception {
        Resource resource = new ClassPathResource(pemFilePath);
        String pemContent = new String(Files.readAllBytes(Paths.get(resource.getURI())));        
        String privateKeyPEM = pemContent.replace("-----BEGIN PRIVATE KEY-----", "")
                                        .replace("-----END PRIVATE KEY-----", "")
                                        .replaceAll("\\s", "");
        return privateKeyPEM;
    }


    public String getPartnerPublicKey() {
        return partnerPublicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }
}
