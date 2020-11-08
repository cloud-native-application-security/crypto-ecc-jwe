package com.example.util;

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

public class EllipticCurveEncryptor {

  private final OctetKeyPair keyPair;

  public EllipticCurveEncryptor(String jwk) {
    try {
      this.keyPair = JWK.parse(jwk).toOctetKeyPair();
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPublicKey() {
    return keyPair.toPublicJWK().toJSONString();
  }

  public String encrypt(String data) {
    try {
      JWEHeader header = new JWEHeader(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM);
      Payload payload = new Payload(data);
      JWEObject jweObject = new JWEObject(header, payload);
      jweObject.encrypt(new X25519Encrypter(this.keyPair));
      return jweObject.serialize();
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  public String keyPairJson() {
    return this.keyPair.toJSONString();
  }
}
