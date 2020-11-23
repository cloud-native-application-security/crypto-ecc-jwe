package com.example.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import java.text.ParseException;

public class EllipticCurveDecrypter {

  private final OctetKeyPair keyPair;

  public EllipticCurveDecrypter() {
    try {
      this.keyPair = new OctetKeyPairGenerator(Curve.X25519).generate();
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPublicKey() {
    return keyPair.toPublicJWK().toJSONString();
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

  public String getPeerPublicKey(String jwe) {
    try {
      JWEObject jweObject = JWEObject.parse(jwe);
      return jweObject.getHeader().getEphemeralPublicKey().toJSONString();
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }
}
