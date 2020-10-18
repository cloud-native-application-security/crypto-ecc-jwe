package com.example.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class KeyExchangeTest {

  @Test
  void testKeyExchange() {
    var alice = new KeyExchange();
    var bob = new KeyExchange();

    var key1 = alice.establishAes256bitKey(bob.getPublicKey());
    var key2 = bob.establishAes256bitKey(alice.getPublicKey());
    var key3 = alice.establishAes256bitKey(bob.getPublicKey());
    var key4 = bob.establishAes256bitKey(alice.getPublicKey());

    assertThat(key1).isEqualTo(key2);
    assertThat(key1.length).isEqualTo(32);
    assertThat(key1).isEqualTo(key3);
    assertThat(key3).isEqualTo(key4);

    alice = new KeyExchange();
    bob = new KeyExchange();

    key3 = alice.establishAes256bitKey(bob.getPublicKey());
    key4 = bob.establishAes256bitKey(alice.getPublicKey());

    assertThat(key1).isNotEqualTo(key3);
    assertThat(key3).isEqualTo(key4);
  }
}
