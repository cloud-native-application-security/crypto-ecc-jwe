package com.example.payments;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import java.text.ParseException;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class PaymentsController {

  @GetMapping("/")
  public String processRefunds() {
    try {

      OctetKeyPair octetKeyPair = new OctetKeyPairGenerator(Curve.X25519).generate();
      var publicKey = octetKeyPair.toPublicJWK().toJSONString();

      var restTemplate = new RestTemplate();
      restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
      var responseJwe =
          restTemplate.postForObject("http://localhost:8082/refunds", publicKey, String.class);

      var refundsJWE = JWEObject.parse(responseJwe);
      refundsJWE.decrypt(new X25519Decrypter(octetKeyPair));
      var refundsJson = refundsJWE.getPayload().toString();

      System.out.println("Refunds JWE : " + refundsJWE);
      System.out.println(
          "Warehouse public key: " + refundsJWE.getHeader().getEphemeralPublicKey().toJSONString());
      System.out.println("Payments key pair: " + octetKeyPair.toJSONString());
      System.out.println("Decrypted Refunds ...");
      System.out.println(refundsJson);
      return refundsJson;

    } catch (JOSEException | ParseException e) {
      throw new RuntimeException(e);
    }
  }
}
