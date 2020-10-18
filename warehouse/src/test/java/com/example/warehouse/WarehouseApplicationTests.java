package com.example.warehouse;

import com.example.util.CryptoUtils;
import com.example.util.JsonUtils;
import com.example.util.KeyExchange;
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
  void testReportGeneration() {
    var keyExchange = new KeyExchange();
    var request = new ReportRequest();
    request.setPublicKey(keyExchange.getPublicKey());

    var url = "http://localhost:" + port + "/refunds";
    var response = restTemplate.postForObject(url, request, ReportResponse.class);
    var decryptionKey = keyExchange.establishAes256bitKey(response.getPublicKey());
    var reportJson = CryptoUtils.decryptJwe(response.getReport(), decryptionKey);
    Refund[] refunds = JsonUtils.fromJson(reportJson, Refund[].class);
    Assertions.assertThat(refunds).hasSize(2);
  }
}
