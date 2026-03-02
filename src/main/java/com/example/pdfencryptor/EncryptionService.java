package com.example.pdfencryptor;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

@Service
public class EncryptionService {

    private static final String AES = "AES";
    private static final String RSA = "RSA";
    
    // For demonstration, we generate a static RSA pair on startup. 
    // In production, you would load these from a KeyStore.
    private final KeyPair serverRsaKeyPair;

    // A static AES key for the "Symmetric" demo option
    private final SecretKey staticAesKey;

    public EncryptionService() throws Exception {
        // Generate RSA Keys
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
        keyGen.initialize(2048);
        this.serverRsaKeyPair = keyGen.generateKeyPair();

        // Generate Static AES Key
        KeyGenerator aesGen = KeyGenerator.getInstance(AES);
        aesGen.init(256);
        this.staticAesKey = aesGen.generateKey();
    }

    /**
     * Standard Symmetric Encryption (AES)
     */
    public byte[] encryptSymmetric(byte[] fileData) throws Exception {
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.ENCRYPT_MODE, staticAesKey);
        return cipher.doFinal(fileData);
    }

    /**
     * Hybrid Asymmetric Encryption.
     * 1. Generate a random AES key.
     * 2. Encrypt file with AES key.
     * 3. Encrypt AES key with RSA Public Key.
     * 4. Prepend Encrypted Key length and Encrypted Key to the file data.
     */
    public byte[] encryptAsymmetric(byte[] fileData) throws Exception {
        // 1. Generate a one-time AES key for this specific file
        KeyGenerator generator = KeyGenerator.getInstance(AES);
        generator.init(256);
        SecretKey oneTimeKey = generator.generateKey();

        // 2. Encrypt the PDF with the one-time AES key
        Cipher aesCipher = Cipher.getInstance(AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, oneTimeKey);
        byte[] encryptedFile = aesCipher.doFinal(fileData);

        // 3. Encrypt the one-time AES key with RSA Public Key
        Cipher rsaCipher = Cipher.getInstance(RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverRsaKeyPair.getPublic());
        byte[] encryptedKey = rsaCipher.doFinal(oneTimeKey.getEncoded());

        // 4. Combine: [Key Length (4 bytes)] + [Encrypted Key] + [Encrypted File]
        // This allows the receiver to parse and decrypt later.
        byte[] result = new byte[4 + encryptedKey.length + encryptedFile.length];
        
        // Store length of the encrypted key
        int keyLength = encryptedKey.length;
        result[0] = (byte) (keyLength >> 24);
        result[1] = (byte) (keyLength >> 16);
        result[2] = (byte) (keyLength >> 8);
        result[3] = (byte) (keyLength);

        System.arraycopy(encryptedKey, 0, result, 4, encryptedKey.length);
        System.arraycopy(encryptedFile, 0, result, 4 + encryptedKey.length, encryptedFile.length);

        return result;
    }

    /**
     * Decrypt Symmetric (AES)
     */
    public byte[] decryptSymmetric(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, staticAesKey);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Decrypt Asymmetric (RSA Hybrid)
     */
    public byte[] decryptAsymmetric(byte[] encryptedData) throws Exception {
        // 1. Extract Key Length
        int keyLength = ((encryptedData[0] & 0xFF) << 24) |
                        ((encryptedData[1] & 0xFF) << 16) |
                        ((encryptedData[2] & 0xFF) << 8) |
                        (encryptedData[3] & 0xFF);

        // 2. Extract Encrypted Key
        byte[] encryptedKey = new byte[keyLength];
        System.arraycopy(encryptedData, 4, encryptedKey, 0, keyLength);

        // 3. Extract Encrypted File Content
        int fileStart = 4 + keyLength;
        int fileLength = encryptedData.length - fileStart;
        byte[] encryptedFile = new byte[fileLength];
        System.arraycopy(encryptedData, fileStart, encryptedFile, 0, fileLength);

        // 4. Decrypt the AES Key with RSA Private Key
        Cipher rsaCipher = Cipher.getInstance(RSA);
        rsaCipher.init(Cipher.DECRYPT_MODE, serverRsaKeyPair.getPrivate());
        byte[] decodedKey = rsaCipher.doFinal(encryptedKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, AES);

        // 5. Decrypt the File with the AES Key
        Cipher aesCipher = Cipher.getInstance(AES);
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
        return aesCipher.doFinal(encryptedFile);
    }
}
