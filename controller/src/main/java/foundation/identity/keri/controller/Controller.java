package foundation.identity.keri.controller;

import foundation.identity.keri.IdentifierKeyStore;
import foundation.identity.keri.KeyConfigurationDigester;
import foundation.identity.keri.KeyEventProcessor;
import foundation.identity.keri.KeyEventStore;
import foundation.identity.keri.KeyStateProcessor;
import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.controller.spec.IdentifierSpec;
import foundation.identity.keri.controller.spec.InteractionSpec;
import foundation.identity.keri.controller.spec.RotationSpec;
import foundation.identity.keri.crypto.DigestAlgorithm;
import foundation.identity.keri.crypto.SignatureAlgorithm;
import foundation.identity.keri.crypto.SignatureOperations;
import foundation.identity.keri.crypto.StandardDigestAlgorithms;
import foundation.identity.keri.crypto.StandardSignatureAlgorithms;
import foundation.identity.keri.internal.event.ImmutableEventSignature;
import foundation.identity.keri.internal.event.ImmutableKeyCoordinates;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static foundation.identity.keri.SigningThresholds.unweighted;

public final class Controller {

  private static final DigestAlgorithm DEFAULT_DIGEST_ALGO = StandardDigestAlgorithms.BLAKE3_256;
  private static final SignatureAlgorithm DEFAULT_SIGNATURE_ALGO = StandardSignatureAlgorithms.ED_25519;

  private final KeyEventStore keyEventStore;
  private final IdentifierKeyStore keyStore;
  private final SecureRandom secureRandom;

  private final EventFactory eventFactory = new EventFactory();
  private final KeyEventProcessor keyEventValidator;

  public Controller(KeyEventStore keyEventStore, IdentifierKeyStore keyStore, SecureRandom secureRandom) {
    this.keyEventStore = keyEventStore;
    this.keyStore = keyStore;
    this.secureRandom = secureRandom;
    this.keyEventValidator = new KeyEventProcessor(keyEventStore);
  }

  private KeyPair generateKeyPair(SignatureAlgorithm algorithm) {
    var ops = SignatureOperations.lookup(algorithm);
    return ops.generateKeyPair(this.secureRandom);
  }

  /**
   * Creates a new private identifier (a.k.a. direct mode).
   *
   * @return a new identifier built with default algorithms
   */
  public ControllableIdentifier newPrivateIdentifier() {
    var initialKeyPair = this.generateKeyPair(DEFAULT_SIGNATURE_ALGO);
    var nextKeyPair = this.generateKeyPair(DEFAULT_SIGNATURE_ALGO);
    var nextKeys = KeyConfigurationDigester.digest(unweighted(1), List.of(nextKeyPair.getPublic()), DEFAULT_DIGEST_ALGO);

    var spec = IdentifierSpec.builder()
        .selfAddressing(DEFAULT_DIGEST_ALGO)
        .key(initialKeyPair.getPublic())
        .nextKeys(nextKeys)
        .signer(0, initialKeyPair.getPrivate())
        .build();

    var event = this.eventFactory.inception(spec);
    this.keyEventValidator.process(event);

    var keyCoordinates = ImmutableKeyCoordinates.of(event, 0);
    this.keyStore.storeKey(keyCoordinates, initialKeyPair);
    this.keyStore.storeNextKey(keyCoordinates, nextKeyPair);

    var state = KeyStateProcessor.apply(null, event);

    return new DefaultControllableIdentifier(this, state);
  }

  public ControllableIdentifier newPublicIdentifier(BasicIdentifier... witnesses) {
    var initialKeyPair = this.generateKeyPair(DEFAULT_SIGNATURE_ALGO);
    var nextKeyPair = this.generateKeyPair(DEFAULT_SIGNATURE_ALGO);
    var nextKeys = KeyConfigurationDigester.digest(unweighted(1), List.of(nextKeyPair.getPublic()), DEFAULT_DIGEST_ALGO);

    var spec = IdentifierSpec.builder()
        .selfAddressing(DEFAULT_DIGEST_ALGO)
        .key(initialKeyPair.getPublic())
        .nextKeys(nextKeys)
        .witnesses(Arrays.asList(witnesses))
        .build();

    var event = this.eventFactory.inception(spec);
    var newState = this.keyEventValidator.process(event);

    var keyCoordinates = ImmutableKeyCoordinates.of(event, 0);

    this.keyStore.storeKey(keyCoordinates, initialKeyPair);
    this.keyStore.storeNextKey(keyCoordinates, nextKeyPair);

    return new DefaultControllableIdentifier(this, newState);
  }

  public ControllableIdentifier newDelegatedIdentifier(Identifier delegator) {
    return null;
  }

  public KeyState rotate(Identifier identifier) {
    return this.rotate(identifier, List.of());
  }

  public KeyState rotate(Identifier identifier, List<Seal> seals) {
    var state = this.keyEventStore.getKeyState(identifier)
        .orElseThrow(() -> new IllegalArgumentException("identifier not found in event store"));

    if (state == null) {
      throw new IllegalArgumentException("identifier state not found in event store");
    }

    // require single keys, nextKeys
    if (state.nextKeyConfigurationDigest().isEmpty()) {
      throw new IllegalArgumentException("identifier cannot be rotated");
    }

    var currentKeyCoordinates = ImmutableKeyCoordinates.of(state.lastEstablishmentEvent(), 0);
    var nextKeyPair = this.keyStore.getNextKey(currentKeyCoordinates);

    if (nextKeyPair.isEmpty()) {
      throw new IllegalArgumentException("next key pair for identifier not found in keystore");
    }

    var newNextKeyPair = this.generateKeyPair(DEFAULT_SIGNATURE_ALGO);
    var nextKeys = KeyConfigurationDigester.digest(unweighted(1), List.of(newNextKeyPair.getPublic()), DEFAULT_DIGEST_ALGO);

    var spec = RotationSpec.builder(state)
        .key(nextKeyPair.get().getPublic())
        .nextKeys(nextKeys)
        .signer(0, nextKeyPair.get().getPrivate())
        .seals(seals)
        .build();


    var event = this.eventFactory.rotation(spec);
    var newState = this.keyEventValidator.process(event);

    var nextKeyCoordinates = ImmutableKeyCoordinates.of(event, 0);
    this.keyStore.storeKey(nextKeyCoordinates, nextKeyPair.get());
    this.keyStore.storeNextKey(nextKeyCoordinates, newNextKeyPair);
    this.keyStore.removeKey(currentKeyCoordinates);
    this.keyStore.removeNextKey(currentKeyCoordinates);

    return newState;
  }

  public KeyState seal(Identifier identifier, List<Seal> seals) {
    var state = this.keyEventStore.getKeyState(identifier)
        .orElseThrow(() -> new IllegalArgumentException("identifier not found in event store"));

    if (state == null) {
      throw new IllegalArgumentException("identifier not found in event store");
    }

    var currentKeyCoordinates = ImmutableKeyCoordinates.of(state.lastEstablishmentEvent(), 0);
    var keyPair = this.keyStore.getKey(currentKeyCoordinates);

    if (keyPair.isEmpty()) {
      throw new IllegalArgumentException("key pair for identifier not found in keystore");
    }

    var spec = InteractionSpec.builder(state)
        .signer(0, keyPair.get().getPrivate())
        .seals(seals)
        .build();

    var event = this.eventFactory.interaction(spec);
    return this.keyEventValidator.process(event);
  }

  public EventSignature sign(Identifier identifier, KeyEvent event) {
    var state = this.keyEventStore.getKeyState(identifier)
        .orElseThrow(() -> new IllegalArgumentException("identifier not found in event store"));

    var keyCoords = ImmutableKeyCoordinates.of(state.lastEstablishmentEvent(), 0);
    var keyPair = this.keyStore.getKey(keyCoords)
        .orElseThrow(() -> new IllegalArgumentException("key pair not found for prefix: " + identifier));

    var ops = SignatureOperations.lookup(keyPair.getPrivate());
    var signature = ops.sign(event.bytes(), keyPair.getPrivate());

    return new ImmutableEventSignature(
        event.coordinates(),
        state.lastEstablishmentEvent().coordinates(),
        Map.of(0, signature));
  }

}
