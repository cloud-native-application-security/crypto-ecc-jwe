package com.example.warehouse;

import com.example.util.KeyExchange;
import java.util.Base64;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class RefundController {

  private final RefundService refundService;

  RefundController(RefundService refundService) {
    this.refundService = refundService;
  }

  @PostMapping("/refunds")
  ReportResponse generateReport(@RequestBody ReportRequest request) {
    var keyExchange = new KeyExchange();
    byte[] encryptionKey = keyExchange.establishAes256bitKey(request.getPublicKey());

    System.out.println(
        "Encrypting with key " + Base64.getUrlEncoder().encodeToString(encryptionKey));
    var response = new ReportResponse();
    response.setPublicKey(keyExchange.getPublicKey());
    response.setReport(refundService.generateEncryptedReport(encryptionKey));
    return response;
  }
}
