package com.quidcash.quidapp.dto;

public class EncryptedDataDTO {

    private String payload;
    private String signature;
    private String secretKey;

    public EncryptedDataDTO(String signature, String payload, String secretKey) {
        this.payload = payload;
        this.signature = signature;
        this.secretKey = secretKey;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }
}

