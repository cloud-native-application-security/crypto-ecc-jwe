package com.example.warehouse;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import java.text.ParseException;
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

    try {
      var payload = new Payload(refundService.generateReport());
      var jweHeader = new JWEHeader(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM);
      var jweObject = new JWEObject(jweHeader, payload);

      OctetKeyPair peerPublicKey = JWK.parse(peerJwk).toOctetKeyPair();
      jweObject.encrypt(new X25519Encrypter(peerPublicKey));

      System.out.println("Response encrypted for owner of public key: " + peerJwk);

      return jweObject.serialize();
    } catch (ParseException | JOSEException e) {
      throw new RuntimeException(e);
    }
  }
}
