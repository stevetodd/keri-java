package foundation.identity.keri.controller.spec;

import foundation.identity.keri.KeyConfigurationDigester;
import foundation.identity.keri.SigningThresholds;
import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.api.crypto.StandardDigestAlgorithms;
import foundation.identity.keri.api.crypto.StandardFormats;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.internal.event.ImmutableIdentifierEventCoordinatesWithDigest;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static java.util.Objects.requireNonNull;

public class RotationSpec {

  private final Format format;

  private final Identifier identifier;
  private final BigInteger sequenceNumber;
  private final IdentifierEventCoordinatesWithDigest previous;

  private final SigningThreshold signingThreshold;
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
      SigningThreshold signingThreshold,
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

  public SigningThreshold signingThreshold() {
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

    private Format format = StandardFormats.JSON;

    // key configuration
    private SigningThreshold signingThreshold;
    private final List<PublicKey> keys = new ArrayList<>();
    private Signer signer;


    // next key configuration
    private SigningThreshold nextSigningThreshold;

    // provide nextKeys + digest algo, nextKeyDigests + digest algo, or nextKeysDigest
    private final DigestAlgorithm nextKeysAlgorithm = StandardDigestAlgorithms.BLAKE3_256;
    private final List<PublicKey> listOfNextKeys = new ArrayList<>();
    private final List<Digest> listOfNextKeyDigests = new ArrayList<>();
    private KeyConfigurationDigest nextKeyConfigurationDigest = KeyConfigurationDigest.NONE;

    private final List<Seal> seals = new ArrayList<>();

    private int witnessThreshold = 0;
    private final List<BasicIdentifier> witnesses = new ArrayList<>();

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

    public Builder signingThreshold(SigningThreshold signingThreshold) {
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

    public Builder signer(PrivateKey privateKey) {
      requireNonNull(privateKey);

      this.signer = new PrivateKeySigner(privateKey);

      return this;
    }

    public Builder nextSigningThreshold(SigningThreshold nextSigningThreshold) {
      this.nextSigningThreshold = requireNonNull(nextSigningThreshold);
      return this;
    }

    public Builder nextSigningThreshold(int nextSigningThreshold) {
      if (nextSigningThreshold < 1) {
        throw new IllegalArgumentException("nextSigningThreshold must be 1 or greater");
      }

      this.nextSigningThreshold = SigningThresholds.unweighted(nextSigningThreshold);

      return this;
    }

    public Builder nextKeys(KeyConfigurationDigest nextKeysDigest) {
      requireNonNull(nextKeysDigest);

      this.nextKeyConfigurationDigest = nextKeysDigest;

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

    public Builder removeWitness(BasicIdentifier identifier) {
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
        throw new IllegalArgumentException("No keys provided.");
      }

      if (this.signingThreshold == null) {
        this.signingThreshold = SigningThresholds.unweighted((this.keys.size() / 2) + 1);
      }

      if (this.signingThreshold instanceof SigningThreshold.Unweighted) {
        var unw = (SigningThreshold.Unweighted) this.signingThreshold;
        if (unw.threshold() > this.keys.size()) {
          throw new IllegalArgumentException(
              "Invalid unweighted signing threshold:"
                  + " keys: " + this.keys.size()
                  + " threshold: " + unw.threshold());
        }
      } else if (this.signingThreshold instanceof SigningThreshold.Weighted) {
        var w = (SigningThreshold.Weighted) this.signingThreshold;
        var countOfWeights = w.weights().stream()
            .mapToLong(Collection::size)
            .sum();
        if (countOfWeights != this.keys.size()) {
          throw new IllegalArgumentException(
              "Count of weights and count of keys are not equal: "
                  + " keys: " + this.keys.size()
                  + " weights: " + countOfWeights);
        }
      } else {
        throw new IllegalArgumentException("Unknown SigningThreshold type: " + this.signingThreshold.getClass());
      }

      // --- NEXT KEYS ---

      if ((!this.listOfNextKeys.isEmpty() && (this.nextKeyConfigurationDigest != null))
          || (!this.listOfNextKeys.isEmpty() && !this.listOfNextKeyDigests.isEmpty())
          || (!this.listOfNextKeyDigests.isEmpty() && (this.nextKeyConfigurationDigest != null))) {
        throw new IllegalArgumentException("Only provide one of nextKeys, nextKeyDigests, or a nextKeys.");
      }

      if (this.nextKeyConfigurationDigest == null) {
        // if we don't have it, we use default of majority nextSigningThreshold
        if (this.nextSigningThreshold == null) {
          this.nextSigningThreshold = SigningThresholds.unweighted((this.keys.size() / 2) + 1);
        } else if (this.nextSigningThreshold instanceof SigningThreshold.Unweighted) {
          var unw = (SigningThreshold.Unweighted) this.nextSigningThreshold;
          if (unw.threshold() > this.keys.size()) {
            throw new IllegalArgumentException(
                "Invalid unweighted signing threshold:"
                    + " keys: " + this.keys.size()
                    + " threshold: " + unw.threshold());
          }
        } else if (this.nextSigningThreshold instanceof SigningThreshold.Weighted) {
          var w = (SigningThreshold.Weighted) this.nextSigningThreshold;
          var countOfWeights = w.weights().stream()
              .mapToLong(Collection::size)
              .sum();
          if (countOfWeights != this.keys.size()) {
            throw new IllegalArgumentException(
                "Count of weights and count of keys are not equal: "
                    + " keys: " + this.keys.size()
                    + " weights: " + countOfWeights);
          }
        } else {
          throw new IllegalArgumentException("Unknown SigningThreshold type: " + this.nextSigningThreshold.getClass());
        }

        if (this.listOfNextKeyDigests.isEmpty()) {
          if (this.listOfNextKeys.isEmpty()) {
            throw new IllegalArgumentException("None of nextKeys, digestOfNextKeys, or nextKeyConfigurationDigest provided");
          }

          this.nextKeyConfigurationDigest = KeyConfigurationDigester.digest(this.nextSigningThreshold, this.listOfNextKeys, this.nextKeysAlgorithm);
        } else {
          this.nextKeyConfigurationDigest = KeyConfigurationDigester.digest(this.nextSigningThreshold, this.listOfNextKeyDigests);
        }
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
          this.nextKeyConfigurationDigest,
          this.witnessThreshold,
          removed,
          added,
          this.seals);
    }

  }

}
