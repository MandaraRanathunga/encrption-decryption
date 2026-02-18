package com.example.pdfencryptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class FileController {

    @Autowired
    private EncryptionService encryptionService;

    @GetMapping("/")
    public String index() {
        return "index"; // Returns index.html
    }

    @PostMapping("/upload")
    public ResponseEntity<ByteArrayResource> uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("algorithm") String algorithm) {

        try {
            byte[] encryptedData;
            String filename = "encrypted_" + file.getOriginalFilename();

            if ("asymmetric".equalsIgnoreCase(algorithm)) {
                encryptedData = encryptionService.encryptAsymmetric(file.getBytes());
            } else {
                encryptedData = encryptionService.encryptSymmetric(file.getBytes());
            }

            ByteArrayResource resource = new ByteArrayResource(encryptedData);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(encryptedData.length)
                    .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }
}
