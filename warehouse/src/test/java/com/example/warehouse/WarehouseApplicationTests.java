package com.example.warehouse;

import com.example.util.JsonUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import java.text.ParseException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.web.client.RestTemplate;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class WarehouseApplicationTests {

  @LocalServerPort private int port;

  private RestTemplate restTemplate = new RestTemplate();

  @Test
  void testReportGeneration() throws JOSEException, ParseException {

    OctetKeyPair octetKeyPair = new OctetKeyPairGenerator(Curve.X25519).generate();
    var publicKey = octetKeyPair.toPublicJWK().toJSONString();

    var url = "http://localhost:" + port + "/refunds";
    var responseJwe = restTemplate.postForObject(url, publicKey, String.class);

    var refundsJWE = JWEObject.parse(responseJwe);
    refundsJWE.decrypt(new X25519Decrypter(octetKeyPair));
    var refundsJson = refundsJWE.getPayload().toString();

    Refund[] refunds = JsonUtils.fromJson(refundsJson, Refund[].class);
    Assertions.assertThat(refunds).hasSize(2);
  }
}
