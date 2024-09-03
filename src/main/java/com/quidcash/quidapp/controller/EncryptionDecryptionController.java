package com.quidcash.quidapp.controller;

import com.quidcash.quidapp.dto.EncryptedDataDTO;
import com.quidcash.quidapp.service.EncryptionDecryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class EncryptionDecryptionController {

    @Autowired
    private EncryptionDecryptionService encryptionDecryptionService;

    // Encrypt Api
    @PostMapping("/encrypt")
    public EncryptedDataDTO encryptPayload(@RequestBody Object requestDTO) throws Exception {
        return encryptionDecryptionService.signAndEncryptData(requestDTO);
    }

    // Decrypt Api
    @PostMapping("/decrypt")
    public Object decryptPayload(@RequestBody EncryptedDataDTO encryptedRequest) throws Exception {
        return encryptionDecryptionService.verifyAndDecryptRequest(encryptedRequest);
    } 
}
