package com.example.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import java.text.ParseException;

public class EllipticCurveCipher {

  private final OctetKeyPair keyPair;

  public EllipticCurveCipher() {
    try {
      this.keyPair = new OctetKeyPairGenerator(Curve.X25519).generate();
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPublicKey() {
    return keyPair.toPublicJWK().toJSONString();
  }

  public String encrypt(String data, String peerJwk) {

    try {
      JWEHeader header = new JWEHeader(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM);
      Payload payload = new Payload(data);
      JWEObject jweObject = new JWEObject(header, payload);
      OctetKeyPair peerPublicKey = JWK.parse(peerJwk).toOctetKeyPair();
      jweObject.encrypt(new X25519Encrypter(peerPublicKey));
      return jweObject.serialize();
    } catch (ParseException | JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  public String decrypt(String jwe) {
    try {
      JWEObject jweObject = JWEObject.parse(jwe);
      jweObject.decrypt(new X25519Decrypter(keyPair));
      return jweObject.getPayload().toString();
    } catch (ParseException | JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  public String keyPairJson() {
    return this.keyPair.toJSONString();
  }

  public String getPeerPublicKey(String jwe) {
    try {
      JWEObject jweObject = JWEObject.parse(jwe);
      return jweObject.getHeader().getEphemeralPublicKey().toJSONString();
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }
}
