package foundation.identity.keri.controller;

import foundation.identity.keri.Hex;
import foundation.identity.keri.KeyConfigurationDigester;
import foundation.identity.keri.api.event.SigningThreshold.Unweighted;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.eventstorage.inmemory.InMemoryKeyEventStore;
import foundation.identity.keri.internal.event.ImmutableKeyCoordinates;
import foundation.identity.keri.internal.event.ImmutableKeyEventCoordinates;
import foundation.identity.keri.internal.seal.ImmutableDigestSeal;
import foundation.identity.keri.internal.seal.ImmutableKeyEventCoordinatesSeal;
import foundation.identity.keri.internal.seal.ImmutableMerkleTreeRootSeal;
import foundation.identity.keri.keystorage.inmemory.InMemoryIdentifierKeyStore;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

import static foundation.identity.keri.SigningThresholds.unweighted;
import static org.junit.Assert.*;

public class ControllerTests {

  SecureRandom secureRandom = new SecureRandom(new byte[]{0});
  final InMemoryKeyEventStore testEventStore = new InMemoryKeyEventStore();
  final InMemoryIdentifierKeyStore testKeyStore = new InMemoryIdentifierKeyStore();

  @BeforeClass
  public static void beforeClass() {
    // secp256k1 is considered "unsecure" so you have enable it like this:
    System.setProperty("jdk.sunec.disableNative", "false");
  }

  @Before
  public void beforeEachTest() throws NoSuchAlgorithmException {
    // this makes the values of secureRandom deterministic
    this.secureRandom = SecureRandom.getInstance("SHA1PRNG");
    this.secureRandom.setSeed(new byte[]{0});
  }

  @Test
  public void test_newPrivateIdentifier() {
    var controller = new Controller(this.testEventStore, this.testKeyStore, this.secureRandom);

    var i = controller.newPrivateIdentifier();

    // identifier
    assertTrue(i.identifier() instanceof SelfAddressingIdentifier);
    var sap = (SelfAddressingIdentifier) i.identifier();
    assertEquals("BLAKE3-256", sap.digest().algorithm().algorithmName());
    assertArrayEquals(
        Hex.unhex("c72586fae3ac9f3542dc6349f892072a4cfa4d63bb6e23d32935e239e2ace741"),
        sap.digest().bytes());

    assertEquals(1, ((Unweighted)i.signingThreshold()).threshold());

    // keys
    assertEquals(1, i.keys().size());
    assertNotNull(i.keys().get(0));

    assertEquals(i.keys().get(0), i.lastEstablishmentEvent().keys().get(0));

    var keyCoordinates = ImmutableKeyCoordinates.of(i.lastEstablishmentEvent(), 0);
    var keyStoreKeyPair = this.testKeyStore.getKey(keyCoordinates);
    assertTrue(keyStoreKeyPair.isPresent());
    assertEquals(keyStoreKeyPair.get().getPublic(), i.keys().get(0));

    // nextKeys
    assertTrue(i.nextKeyConfigurationDigest().isPresent());
    var keyStoreNextKeyPair = this.testKeyStore.getNextKey(keyCoordinates);
    assertTrue(keyStoreNextKeyPair.isPresent());
    var expectedNextKeys = KeyConfigurationDigester.digest(
        unweighted(1),
        List.of(keyStoreNextKeyPair.get().getPublic()),
        i.nextKeyConfigurationDigest().get().algorithm());
    assertEquals(expectedNextKeys, i.nextKeyConfigurationDigest().get());

    // witnesses
    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());

    // config
    assertEquals(0, i.configurationTraits().size());

    // lastEstablishmentEvent
    assertEquals(i.identifier(), i.lastEstablishmentEvent().identifier());
    assertEquals(0, i.lastEstablishmentEvent().sequenceNumber());
    // TODO check digest

    // lastEvent
    assertEquals(i.identifier(), i.lastEvent().identifier());
    assertEquals(0, i.lastEvent().sequenceNumber());
    // TODO digest

    assertEquals(i.lastEvent(), i.lastEstablishmentEvent());

    // delegation
    assertFalse(i.delegatingIdentifier().isPresent());
    assertFalse(i.delegated());
  }

  @Test
  public void test_privateIdentifier_rotate() {
    var controller = new Controller(this.testEventStore, this.testKeyStore, this.secureRandom);

    var i = controller.newPrivateIdentifier();

    var digest = DigestOperations.BLAKE3_256.digest("digest seal".getBytes());
    var event = ImmutableKeyEventCoordinates.of(i.lastEstablishmentEvent());

    i.rotate(
        List.of(
            new ImmutableDigestSeal(digest),
            new ImmutableMerkleTreeRootSeal(digest),
            new ImmutableKeyEventCoordinatesSeal(event)
        ));

    i.rotate();
  }

  @Test
  public void test_privateIdentifier_interaction() {
    var controller = new Controller(this.testEventStore, this.testKeyStore, this.secureRandom);

    var i = controller.newPrivateIdentifier();

    var digest = DigestOperations.BLAKE3_256.digest("digest seal".getBytes());
    var event = ImmutableKeyEventCoordinates.of(i.lastEstablishmentEvent());
    var seals = List.of(
        new ImmutableDigestSeal(digest),
        new ImmutableMerkleTreeRootSeal(digest),
        new ImmutableKeyEventCoordinatesSeal(event)
    );

    i.rotate();
    i.seal(List.of());
    i.rotate(seals);
    i.seal(seals);
  }

}
