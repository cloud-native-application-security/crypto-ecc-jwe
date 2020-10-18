package com.example.util;

import com.google.crypto.tink.subtle.Hkdf;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.KeyAgreement;

public class NistP256KeyExchange {

  private final KeyPair keyPair;

  public NistP256KeyExchange() {
    try {
      var keyPairGenerator = KeyPairGenerator.getInstance("EC");
      keyPairGenerator.initialize(256);
      this.keyPair = keyPairGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPublicKey() {
    byte[] publicKey = keyPair.getPublic().getEncoded();
    return Base64.getUrlEncoder().encodeToString(publicKey);
  }

  public byte[] establishAes256bitKey(String peerPublicKey) {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
      keyAgreement.init(keyPair.getPrivate());

      keyAgreement.doPhase(fromBase64(peerPublicKey), true);
      byte[] secret = keyAgreement.generateSecret();

      return Hkdf.computeHkdf("HMACSHA256", secret, null, null, 32);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  private PublicKey fromBase64(String peerPublicKeyInBase64Url)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    var peerPublicKeyBytes = Base64.getUrlDecoder().decode(peerPublicKeyInBase64Url);
    var publicKeySpec = new X509EncodedKeySpec(peerPublicKeyBytes);
    return keyFactory.generatePublic(publicKeySpec);
  }
}
