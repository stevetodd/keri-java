package foundation.identity.keri.controller.spec;

import foundation.identity.keri.KeyConfigurationDigester;
import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.api.crypto.StandardDigestAlgorithms;
import foundation.identity.keri.api.crypto.StandardFormats;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.internal.event.ImmutableIdentifierEventCoordinatesWithDigest;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

public class RotationSpec {

  private final Format format;

  private final Identifier identifier;
  private final BigInteger sequenceNumber;
  private final IdentifierEventCoordinatesWithDigest previous;

  private final int signingThreshold;
  private final List<PublicKey> keys;
  private final Signer signer;

  private final KeyConfigurationDigest nextKeys;

  private final int witnessThreshold;
  private final List<BasicIdentifier> addedWitnesses;
  private final List<BasicIdentifier> removedWitnesses;

  private final List<Seal> seals;

  public RotationSpec(
      Format format,
      Identifier identifier,
      BigInteger sequenceNumber,
      IdentifierEventCoordinatesWithDigest previousEvent,
      int signingThreshold,
      List<PublicKey> keys,
      Signer signer,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
      List<BasicIdentifier> removedWitnesses,
      List<BasicIdentifier> addedWitnesses,
      List<Seal> seals) {
    this.format = format;
    this.identifier = identifier;
    this.sequenceNumber = sequenceNumber;
    this.previous = previousEvent;
    this.signingThreshold = signingThreshold;
    this.keys = List.copyOf(keys);
    this.signer = signer;
    this.nextKeys = nextKeys;
    this.witnessThreshold = witnessThreshold;
    this.addedWitnesses = List.copyOf(addedWitnesses);
    this.removedWitnesses = List.copyOf(removedWitnesses);
    this.seals = List.copyOf(seals);
  }

  public static Builder builder(IdentifierState state) {
    return new Builder(state);
  }

  public Identifier identifier() {
    return this.identifier;
  }

  public BigInteger sequenceNumber() {
    return this.sequenceNumber;
  }

  public IdentifierEventCoordinatesWithDigest previous() {
    return this.previous;
  }

  public Format format() {
    return this.format;
  }

  public int signingThreshold() {
    return this.signingThreshold;
  }

  public List<PublicKey> keys() {
    return this.keys;
  }

  public Signer signer() {
    return this.signer;
  }

  public KeyConfigurationDigest nextKeys() {
    return this.nextKeys;
  }

  public int witnessThreshold() {
    return this.witnessThreshold;
  }

  public List<BasicIdentifier> addedWitnesses() {
    return this.addedWitnesses;
  }

  public List<BasicIdentifier> removedWitnesses() {
    return this.removedWitnesses;
  }

  public List<Seal> seals() {
    return this.seals;
  }

  public static class Builder {
    private final IdentifierState state;
    private final List<PublicKey> keys = new ArrayList<>();
    private final List<Digest> nextKeyDigests = new ArrayList<>();
    private final List<PublicKey> nextKeys = new ArrayList<>();
    private final List<BasicIdentifier> witnesses = new ArrayList<>();
    private final List<Seal> seals = new ArrayList<>();
    private final DigestAlgorithm nextKeysAlgorithm = StandardDigestAlgorithms.BLAKE3_256;
    private Format format = StandardFormats.JSON;
    private int signingThreshold = 0;
    private Signer signer;
    private KeyConfigurationDigest nextKeysDigest = KeyConfigurationDigest.NONE;
    private int nextSigningThreshold = 0;
    private int witnessThreshold = 0;

    public Builder(IdentifierState state) {
      this.state = state;
    }

    public Builder json() {
      this.format = StandardFormats.JSON;
      return this;
    }

    public Builder cbor() {
      this.format = StandardFormats.CBOR;
      return this;
    }

    public Builder messagePack() {
      this.format = StandardFormats.MESSAGE_PACK;
      return this;
    }

    public Builder signingThreshold(int signingThreshold) {
      this.signingThreshold = signingThreshold;
      return this;
    }

    public Builder key(PublicKey publicKey) {
      requireNonNull(publicKey);
      this.keys.add(publicKey);
      return this;
    }

    public Builder keys(List<PublicKey> publicKeys) {
      requireNonNull(publicKeys);
      this.keys.addAll(publicKeys);
      return this;
    }

    public Builder signer(Signer signer) {
      requireNonNull(signer);

      this.signer = signer;

      return this;
    }

    public Builder signer(int keyIndex, PrivateKey privateKey) {
      if (keyIndex < 0) {
        throw new IllegalArgumentException("keyIndex must be >= 0");
      }

      requireNonNull(privateKey);

      this.signer = new PrivateKeySigner(keyIndex, privateKey);

      return this;
    }

    public Builder nextSigningThreshold(int nextSigningThreshold) {
      if (nextSigningThreshold < 1) {
        throw new IllegalArgumentException("nextSigningThreshold must be 1 or greater");
      }

      this.nextSigningThreshold = nextSigningThreshold;

      return this;
    }

    public Builder nextKeys(KeyConfigurationDigest nextKeysDigest) {
      requireNonNull(nextKeysDigest);

      this.nextKeysDigest = nextKeysDigest;

      return this;
    }

    public Builder witnessThreshold(int witnessThreshold) {
      this.witnessThreshold = witnessThreshold;
      return this;
    }

    public Builder addWitness(BasicIdentifier prefix) {
      requireNonNull(prefix);
      this.witnesses.add(prefix);
      return this;
    }

    public Builder addWitnesses(List<BasicIdentifier> prefixes) {
      requireNonNull(prefixes);
      this.witnesses.addAll(prefixes);
      return this;
    }

    public Builder addWitnesses(BasicIdentifier... prefixes) {
      requireNonNull(prefixes);
      this.witnesses.addAll(List.of(prefixes));
      return this;
    }

    public Builder removeWitness(Identifier identifier) {
      requireNonNull(identifier);
      this.witnesses.remove(identifier);
      return this;
    }

    public Builder removeWitnesses(List<BasicIdentifier> prefixes) {
      requireNonNull(prefixes);
      this.witnesses.removeAll(prefixes);
      return this;
    }

    public Builder removeWitnesses(BasicIdentifier... prefixes) {
      requireNonNull(prefixes);
      this.witnesses.removeAll(List.of(prefixes));
      return this;
    }

    public Builder seal(Seal seal) {
      requireNonNull(seal);
      this.seals.add(seal);
      return this;
    }

    public Builder seals(List<Seal> seals) {
      requireNonNull(seals);
      this.seals.addAll(seals);
      return this;
    }

    public RotationSpec build() {

      // --- KEYS ---

      if (this.keys.isEmpty()) {
        throw new RuntimeException("No keys provided.");
      }

      if (this.signingThreshold == 0) {
        this.signingThreshold = (this.keys.size() / 2) + 1;
      }

      if ((this.signingThreshold < 1) || (this.signingThreshold > this.keys.size())) {
        throw new RuntimeException(
            "Invalid signing threshold:"
                + " keys: " + this.keys.size()
                + " threshold: " + this.signingThreshold);
      }

      // --- NEXT KEYS ---

      if ((!this.nextKeys.isEmpty() && (this.nextKeys != null))
          || (!this.nextKeys.isEmpty() && !this.nextKeyDigests.isEmpty())
          || (!this.nextKeyDigests.isEmpty() && (this.nextKeys != null))) {
        throw new RuntimeException("Only provide one of nextKeys, nextKeyDigests, or a nextKeys.");
      }

      if (!this.nextKeyDigests.isEmpty()) {

        if (this.nextSigningThreshold == 0) {
          this.nextSigningThreshold = (this.nextKeyDigests.size() / 2) + 1;
        }

        if ((this.nextSigningThreshold < 1) || (this.nextSigningThreshold > this.nextKeyDigests.size())) {
          throw new RuntimeException(
              "Invalid next signing threshold:"
                  + " keys: " + this.nextKeys.size()
                  + " threshold: " + this.nextSigningThreshold);
        }

        this.nextKeysDigest = KeyConfigurationDigester.digest(this.nextSigningThreshold, this.nextKeyDigests);

      } else if (!this.nextKeys.isEmpty()) {

        if (this.nextSigningThreshold == 0) {
          this.nextSigningThreshold = (this.nextKeys.size() / 2) + 1;
        }

        if ((this.nextSigningThreshold < 1) || (this.nextSigningThreshold > this.nextKeys.size())) {
          throw new RuntimeException(
              "Invalid next signing threshold:"
                  + " keys: " + this.nextKeys.size()
                  + " threshold: " + this.nextSigningThreshold);
        }

        this.nextKeysDigest = KeyConfigurationDigester.digest(this.nextSigningThreshold, this.nextKeys,
            this.nextKeysAlgorithm);

      }

      // --- WITNESSES ---
      var added = new ArrayList<>(this.witnesses);
      added.removeAll(this.state.witnesses());

      var removed = new ArrayList<>(this.state.witnesses());
      removed.removeAll(this.witnesses);

      return new RotationSpec(
          this.format,
          this.state.identifier(),
          this.state.lastEvent().sequenceNumber().add(BigInteger.ONE),
          ImmutableIdentifierEventCoordinatesWithDigest.of(this.state.lastEvent()),
          this.signingThreshold,
          this.keys,
          this.signer,
          this.nextKeysDigest,
          this.witnessThreshold,
          removed,
          added,
          this.seals);
    }

  }

}
