package com.example.pdfencryptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class FileController {

    @Autowired
    private EncryptionService encryptionService;

    @PostMapping("/upload")
    public ResponseEntity<ByteArrayResource> uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("algorithm") String algorithm) {

        try {
           byte[] encryptedData;   // ← this is the actual variable name

           // later inside if/else:
        if ("asymmetric".equalsIgnoreCase(algorithm)) {
        encryptedData = encryptionService.encryptAsymmetric(file.getBytes());
             } else {
                 encryptedData = encryptionService.encryptSymmetric(file.getBytes());
                      }

            ByteArrayResource resource = new ByteArrayResource(encryptedData);

             return ResponseEntity.ok()
              .contentType(MediaType.APPLICATION_PDF)
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"encrypted.pdf\"")
        .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }
}
