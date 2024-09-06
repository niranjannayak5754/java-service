package com.niranjan.javaservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.niranjan.javaservice.configuration.PartnerConfiguration;
import com.niranjan.javaservice.dto.EncryptedDataDTO;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for RSA and AES encryption/decryption and digital signature handling.
 * Provides methods for secure data exchange and integrity verification.
 *
 * @author Niranjan Nayak <niranjannayak0717@gmail.com>
 * @since 01/09/2024
 */
@Service
public class EncryptionDecryptionService {

    public static final String DECRYPTED_REQUEST = "decryptedRequest";
    public static final String DECRYPTED_RESPONSE = "decryptedResponse";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_PADDING_SCHEME = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_PADDING_SCHEME = "AES/CBC/PKCS5PADDING";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int AES_KEY_SIZE = 256;
    private static final int LOW_ASCII_LIMIT = 47; // letter '/'
    private static final int HIGH_ASCII_LIMIT = 126; // letter 'z'

    private static final SecureRandom RANDOM = new SecureRandom();

    private final PartnerConfiguration partnerConfiguration;

    public EncryptionDecryptionService(PartnerConfiguration partnerConfiguration) {
        this.partnerConfiguration = partnerConfiguration;
    }

    /**
     * Decrypts an encrypted string using the provided secret key and IV extracted
     * from the first 16 bytes of the payload.
     * <p>
     * The secret key must be 16/24/32 bytes in length after being encoded to bytes.
     * Encryption cipher uses AES/CBC/PKCS5PADDING.
     *
     * @param encryptedData The encrypted string to decrypt.
     * @param secretKey     The secret key used for decryption.
     * @return The decrypted string.
     * @throws Exception If an error occurs during decryption.
     */

    public String decryptPayloadWithAES(String encryptedData, SecretKey secretKey) throws Exception {
        try {
            // Decode the Base64 encoded string
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] secretKeyBytes = secretKey.getEncoded();
            if (secretKeyBytes.length != 16 && secretKeyBytes.length != 24 && secretKeyBytes.length != 32) {
                throw new IllegalArgumentException("Invalid Key Length, Must be 16/24/32 bytes");
            }
            // Extract IV from the combined byte array
            byte[] ivBytes = new byte[16]; // IV length is assumed to be 16 bytes
            System.arraycopy(encryptedBytes, 0, ivBytes, 0, ivBytes.length);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance(AES_PADDING_SCHEME);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            // Decrypt the data
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes, ivBytes.length, encryptedBytes.length - ivBytes.length);

            // Convert decrypted bytes to string and return
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Handle specific exceptions
            throw new Exception("Error decrypting payload with AES: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            // Handle invalid key length
            throw new IllegalArgumentException("Error decrypting payload with AES: " + e.getMessage(), e);
        } catch (Exception e) {
            // Handle any other unexpected exceptions
            throw new Exception("Unexpected error during AES decryption: " + e.getMessage(), e);
        }
    }

    /**
     * Generates a secret key for AES encryption with the specified key size.
     *
     * @param keySize The size of the secret key to generate, in bits.
     * @return The SecretKey object representing the generated AES key.
     * @throws NoSuchAlgorithmException If the AES algorithm is not available.
     */
    private SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
        // Create a KeyGenerator instance for AES algorithm
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        // Initialize the key generator with the specified key size
        keyGenerator.init(keySize);

        // Generate and return the SecretKey object
        return keyGenerator.generateKey();
    }

    /**
     * Encrypts a message using the provided secret key and an internally generated IV.
     * <p>
     * The secret key must be 16/24/32 bytes in length after being encoded to bytes.
     * Encryption cipher uses AES/CBC/PKCS5PADDING.
     *
     * @param dataToEncrypt The message to encrypt.
     * @param secretKey     The secret key used for encryption.
     * @return A BASE64 encoded string representing the IV + Encrypted payload combination.
     * @throws Exception If an error occurs during encryption.
     */
    public String encryptPayloadWithAES(String dataToEncrypt, SecretKey secretKey) throws Exception {
        String initVector = generateIv(); // Generate IV
        // Convert IV String to byte array
        byte[] ivBytes = initVector.getBytes(StandardCharsets.UTF_8);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        byte[] secretKeyBytes = secretKey.getEncoded();
        if (secretKeyBytes.length != 16 && secretKeyBytes.length != 24 && secretKeyBytes.length != 32) {
            throw new IllegalArgumentException("Invalid Key Length, Must be 16/24/32 bytes");
        }
        // Initialize cipher
        Cipher cipher = Cipher.getInstance(AES_PADDING_SCHEME);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // Encrypt the data
        byte[] encryptedBytes = cipher.doFinal(dataToEncrypt.getBytes(StandardCharsets.UTF_8));

        // Combine IV and encrypted bytes
        byte[] finalArray = new byte[ivBytes.length + encryptedBytes.length];
        System.arraycopy(ivBytes, 0, finalArray, 0, ivBytes.length);
        System.arraycopy(encryptedBytes, 0, finalArray, ivBytes.length, encryptedBytes.length);

        // Encode the combined IV and encrypted payload in Base64
        return Base64.getEncoder().encodeToString(finalArray);
    }

    /**
     * Generates a 16-byte IV using random characters within the ASCII range 47-126.
     *
     * @return The generated IV string.
     */
    public String generateIv() {
        int ivLength = 16; // final length of IV String
        StringBuilder finalIvBuffer = new StringBuilder(ivLength);
        for (int i = 0; i < ivLength; i++) {
            int randomNumber = LOW_ASCII_LIMIT + (int) (RANDOM.nextFloat() * (HIGH_ASCII_LIMIT - LOW_ASCII_LIMIT + 1));
            finalIvBuffer.append((char) randomNumber);
        }
        return finalIvBuffer.toString();
    }

    /**
     * Encrypts a secret key using RSA encryption with the provided public key.
     *
     * @param secretKey The secret key to be encrypted.
     * @param publicKey The public key used for encryption.
     * @return The Base64 encoded string representing the encrypted secret key.
     * @throws Exception If an error occurs during encryption.
     */
    public String encryptSecretKeyWithRSA(SecretKey secretKey, PublicKey publicKey) throws Exception {
        //Initialize cipher for encryption with RSA using OAEP with SHA-256 and MGF1 padding scheme
        Cipher cipher = Cipher.getInstance(RSA_PADDING_SCHEME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt the secret key
        byte[] encryptedBytes = cipher.doFinal(secretKey.getEncoded());

        // Encode the encrypted bytes to Base64 string and return
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }


    /**
     * Decrypts a secret key using RSA decryption with the provided private key.
     *
     * @param encryptedKey The Base64 encoded string representing the encrypted secret key.
     * @param privateKey   The private key used for decryption.
     * @return The decrypted secret key.
     * @throws Exception If an error occurs during decryption.
     */
    public SecretKey decryptSecretKeyWithRSA(String encryptedKey, PrivateKey privateKey) throws Exception {
        try {
            // Initialize cipher for decryption with RSA
            Cipher cipher = Cipher.getInstance(RSA_PADDING_SCHEME);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Decrypt the encrypted key
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));

            // Create and return a SecretKey from the decrypted bytes
            return new SecretKeySpec(decryptedBytes, AES_ALGORITHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            // Handle specific exceptions
            throw new Exception("Error decrypting secret key with RSA: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            // Handle Base64 decoding errors
            throw new Exception("Error decoding Base64 encoded encrypted key: " + e.getMessage(), e);
        } catch (Exception e) {
            // Handle any other unexpected exceptions
            throw new Exception("Unexpected error during RSA decryption: " + e.getMessage(), e);
        }
    }

    /**
     * Signs a secret key using RSA signature with the provided private key.
     *
     * @param secretKey  The secret key to be signed.
     * @param privateKey The private key used for signing.
     * @return The Base64 encoded string representing the signature.
     * @throws Exception If an error occurs during signing.
     */
    public String signSecretKeyWithRSA(SecretKey secretKey, PrivateKey privateKey) throws Exception {
        // Initialize signature with RSA algorithm
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);

        // Update the signature with the encoded bytes of the secret key
        signature.update(secretKey.getEncoded());

        // Generate the signature bytes
        byte[] signatureBytes = signature.sign();

        // Encode the signature bytes to Base64 string and return
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * Verifies the signature of a secret key using RSA signature with the provided public key.
     *
     * @param signedKey   The Base64 encoded string representing the signature to be verified.
     * @param originalKey The original secret key whose signature is to be verified.
     * @param publicKey   The public key used for verification.
     * @return True if the signature is verified successfully, false otherwise.
     * @throws Exception If an error occurs during verification.
     */
    public boolean verifySecretKeySignature(String signedKey, SecretKey originalKey, PublicKey publicKey) throws Exception {
        try {
            // Initialize signature with RSA algorithm
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);

            // Update the signature with the encoded bytes of the original key
            signature.update(originalKey.getEncoded());

            // Verify the signature with the provided signed key bytes
            return signature.verify(Base64.getDecoder().decode(signedKey));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            // Handle specific exceptions
            throw new Exception("Error verifying secret key signature: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            // Handle Base64 decoding errors
            throw new IllegalArgumentException("Error decoding Base64 encoded signed key: " + e.getMessage(), e);
        } catch (Exception e) {
            // Handle any other unexpected exceptions
            throw new Exception("Unexpected error during signature verification: " + e.getMessage(), e);
        }
    }


    /**
     * Converts a Base64 encoded string to a byte array.
     *
     * @param base64String The Base64 encoded string to convert.
     * @return The byte array decoded from the Base64 string.
     */
    public byte[] base64ToByteArray(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

//    public KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
//        keyPairGenerator.initialize(keySize);
//        return keyPairGenerator.generateKeyPair();
//    }

//    public void generateKeyPair() throws NoSuchAlgorithmException {
//        KeyPair keyPair = generateRSAKeyPair(KEY_SIZE);
//        PublicKey publicKey = keyPair.getPublic();
//        PrivateKey privateKey = keyPair.getPrivate();
//
//        String base64PublicKey = encodeToBase64(publicKey.getEncoded());
//        String base64PrivateKey = encodeToBase64(privateKey.getEncoded());
//        log.info("Base64 Public Key: " + base64PublicKey);
//        log.info("Base64 Private Key: " + base64PrivateKey);
//    }

    /**
     * Retrieves a public key from a Base64 encoded string representation.
     *
     * @param base64PublicKey The Base64 encoded string representing the public key.
     * @return The PublicKey object decoded from the Base64 string.
     * @throws Exception If an error occurs during the decoding or generation of the public key.
     */
    public PublicKey getPublicKeyFromBase64(String base64PublicKey) throws Exception {
        // Decode the Base64 string to obtain the byte array representation of the key
        byte[] decodedKeyBytes = base64ToByteArray(base64PublicKey);

        // Generate and return the PublicKey object from the decoded key bytes
        return generatePublicKey(decodedKeyBytes);
    }

    /**
     * Retrieves a private key from a Base64 encoded string representation.
     *
     * @param base64PrivateKey The Base64 encoded string representing the private key.
     * @return The PrivateKey object decoded from the Base64 string.
     * @throws Exception If an error occurs during the decoding or generation of the private key.
     */
    public PrivateKey getPrivateKeyFromBase64(String base64PrivateKey) throws Exception {
        // Decode the Base64 string to obtain the byte array representation of the key
        byte[] decodedKeyBytes = base64ToByteArray(base64PrivateKey);

        // Generate and return the PrivateKey object from the decoded key bytes
        return generatePrivateKey(decodedKeyBytes);
    }

    /**
     * Generates a public key from the provided byte array representation.
     *
     * @param keyBytes The byte array representing the public key.
     * @return The PublicKey object generated from the byte array.
     * @throws Exception If an error occurs during the generation of the public key.
     */
    private PublicKey generatePublicKey(byte[] keyBytes) throws Exception {
        // Create a KeyFactory instance for RSA algorithm
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);

        // Create a public key specification from the key bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // Generate and return the PublicKey object from the key specification
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Generates a private key from the provided byte array representation.
     *
     * @param keyBytes The byte array representing the private key.
     * @return The PrivateKey object generated from the byte array.
     * @throws Exception If an error occurs during the generation of the private key.
     */
    private PrivateKey generatePrivateKey(byte[] keyBytes) throws Exception {
        // Create a KeyFactory instance for RSA algorithm
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);

        // Create a private key specification from the key bytes
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        // Generate and return the PrivateKey object from the key specification
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Verifies and decrypts an encrypted request, returning the decrypted data of the specified class type.
     *
     * @param encryptedRequest   The encrypted request to verify and decrypt.
     * @param clazz              The class type to which the decrypted data should be mapped.
     * @param httpServletRequest The HttpServletRequest containing the API key header.
     * @return The decrypted data of the specified class type.
     * @throws ApplicationStandardException If an error occurs during verification, decryption, or mapping of the decrypted data.
     */
    public Object verifyAndDecryptRequest(EncryptedDataDTO encryptedRequest) throws Exception {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String payload = encryptedRequest.getPayload();
            String signature = encryptedRequest.getSignature();
            String partnerPublicKey = partnerConfiguration.getPartnerPublicKey();
            String encryptedSecretKey = encryptedRequest.getSecretKey();

            // Retrieve partner's public key
            if (partnerPublicKey == null) {
                // throw new ApplicationStandardException("ERR-700");
                throw new Exception("Public key not found Error");
            }
            if (encryptedSecretKey == null || encryptedSecretKey.isEmpty()) {
                // throw new ApplicationStandardException("ERR-702");
                throw new Exception("encryptedSecret Key not found Error");
            }
            if (payload == null || payload.isEmpty()) {
                // throw new ApplicationStandardException("ERR-703");
                throw new Exception("Payload not found Error");
            }
            // Decrypt the secret key using RSA
            SecretKey secretKey = decryptSecretKeyWithRSA(encryptedSecretKey, getPrivateKeyFromBase64(partnerConfiguration.getPrivateKey()));

            // Decrypt the payload using AES
            String decryptedData = decryptPayloadWithAES(payload, secretKey);
            System.out.println("Decrypted Data: " + decryptedData);

            // Verify the signature of the decrypted data
            boolean isSign = verifySecretKeySignature(signature, secretKey, getPublicKeyFromBase64(partnerPublicKey));
            if (isSign) {
                System.out.println("Signature Verified");
                // Map the decrypted data to the specified class type
                Object decryptedRequestObject = objectMapper.readValue(decryptedData, Object.class);
                return decryptedRequestObject;
            } else {
                throw new Exception("Error validating signature");
            }
        } catch (IOException e) {
            throw new Exception("Error reading decrypted data: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("Error decrypting or verifying request: " + e.getMessage());
        }
    }


    public EncryptedDataDTO signAndEncryptData(Object data) throws Exception {
        try {
            // Retrieve API key and partner's public key
            String partnerPublicKey = partnerConfiguration.getPartnerPublicKey();

            // Validate partner's public key existence
            if (partnerPublicKey == null) {
                // throw new ApplicationStandardException("ERR-700");
                throw new Exception("Public Key Not found exception");
            }
            // Serialize response data to JSON
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonStr = objectMapper.writeValueAsString(data);

            // Generate AES key and encrypt response data
            SecretKey aesKey = generateAESKey(AES_KEY_SIZE);
            String encryptedMessage = encryptPayloadWithAES(jsonStr, aesKey);

            // Encrypt AES key with partner's public key
            String encryptedAESKey = encryptSecretKeyWithRSA(aesKey, getPublicKeyFromBase64(partnerPublicKey));

            // Sign AES key with server's private key
            String signature = signSecretKeyWithRSA(aesKey, getPrivateKeyFromBase64(partnerConfiguration.getPrivateKey()));

            // Return encrypted request containing signature, encrypted message, and encrypted AES key
            return new EncryptedDataDTO(signature, encryptedMessage, encryptedAESKey);
        } catch (JsonProcessingException | IllegalArgumentException e) {
            // Handle JSON processing exception or missing public key
            throw new Exception("JSON PARSING ERROR: " + e.getMessage());
        } catch (Exception e) {
            throw new Exception("Unexpected error during signing encrypted data: " + e.getMessage(), e);

        }
    }
}
