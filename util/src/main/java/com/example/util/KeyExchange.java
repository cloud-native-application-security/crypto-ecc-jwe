package com.example.util;

import com.google.crypto.tink.subtle.Hkdf;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import javax.crypto.KeyAgreement;

public class KeyExchange {

  private final KeyPair keyPair;
  private final JWK publicKeyJwk;

  public KeyExchange() {
    try {
      var keyPairGenerator = KeyPairGenerator.getInstance("EC");
      keyPairGenerator.initialize(256);
      this.keyPair = keyPairGenerator.generateKeyPair();
      this.publicKeyJwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic()).build();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPublicKey() {
    return this.publicKeyJwk.toJSONString();
  }

  public byte[] establishAes256bitKey(String peerPublicKey) {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
      keyAgreement.init(keyPair.getPrivate());

      PublicKey peerKey = JWK.parse(peerPublicKey).toECKey().toECPublicKey();
      keyAgreement.doPhase(peerKey, true);
      byte[] secret = keyAgreement.generateSecret();

      return Hkdf.computeHkdf("HMACSHA256", secret, null, null, 32);
    } catch (GeneralSecurityException | ParseException | JOSEException e) {
      throw new RuntimeException(e);
    }
  }
}
