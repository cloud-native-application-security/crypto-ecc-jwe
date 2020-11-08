package com.example.warehouse;

import com.example.util.EllipticCurveEncryptor;
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
  String generateReport(@RequestBody String peerJwk) {
    System.out.println("Response encrypted for holder of public key: " + peerJwk);
    var cipher = new EllipticCurveEncryptor(peerJwk);
    return cipher.encrypt(refundService.generateReport());
  }
}
