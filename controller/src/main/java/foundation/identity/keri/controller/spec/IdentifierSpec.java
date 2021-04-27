package foundation.identity.keri.controller.spec;

import foundation.identity.keri.KeyConfigurationDigester;
import foundation.identity.keri.SigningThresholds;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.event.StandardFormats;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;
import foundation.identity.keri.api.identifier.SelfSigningIdentifier;
import foundation.identity.keri.crypto.Digest;
import foundation.identity.keri.crypto.DigestAlgorithm;
import foundation.identity.keri.crypto.StandardDigestAlgorithms;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

public class IdentifierSpec {

  private final Class<? extends Identifier> derivation;
  private final DigestAlgorithm identifierDigestAlgorithm;

  private final Format format;

  private final SigningThreshold signingThreshold;

  private final List<PublicKey> keys;
  private final Signer signer;

  private final KeyConfigurationDigest nextKeys;

  private final int witnessThreshold;
  private final List<BasicIdentifier> witnesses;

  private final Set<ConfigurationTrait> configurationTraits;

  private IdentifierSpec(
      Class<? extends Identifier> derivation,
      DigestAlgorithm identifierDigestAlgorithm,
      Format format,
      SigningThreshold signingThreshold,
      List<PublicKey> keys,
      Signer signer,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
      List<BasicIdentifier> witnesses,
      Set<ConfigurationTrait> configurationTraits) {
    super();
    this.derivation = derivation;
    this.identifierDigestAlgorithm = identifierDigestAlgorithm;
    this.format = format;
    this.signingThreshold = signingThreshold;
    this.keys = List.copyOf(keys);
    this.signer = signer;
    this.nextKeys = nextKeys;
    this.witnessThreshold = witnessThreshold;
    this.witnesses = List.copyOf(witnesses);
    this.configurationTraits = Set.copyOf(configurationTraits);
  }

  public static Builder builder() {
    return new Builder();
  }

  public Class<? extends Identifier> derivation() {
    return this.derivation;
  }

  public DigestAlgorithm selfAddressingDigestAlgorithm() {
    return this.identifierDigestAlgorithm;
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

  public List<BasicIdentifier> witnesses() {
    return this.witnesses;
  }

  public Set<ConfigurationTrait> configurationTraits() {
    return this.configurationTraits;
  }

  public static class Builder {

    private Format format = StandardFormats.JSON;

    // identifier derivation
    private Class<? extends Identifier> derivation = SelfAddressingIdentifier.class;
    private DigestAlgorithm selfAddressingDigestAlgorithm = StandardDigestAlgorithms.BLAKE3_256;

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

    private int witnessThreshold = 0;
    private final List<BasicIdentifier> witnesses = new ArrayList<>();

    private final EnumSet<ConfigurationTrait> configurationTraits = EnumSet.noneOf(ConfigurationTrait.class);

    public Builder basicDerivation(PublicKey key) {
      this.derivation = BasicIdentifier.class;
      this.keys.add(key);
      return this;
    }

    public Builder selfAddressing(DigestAlgorithm algorithm) {
      this.derivation = SelfAddressingIdentifier.class;
      this.selfAddressingDigestAlgorithm = algorithm;
      return this;
    }

    public Builder selfSigning() {
      this.derivation = SelfSigningIdentifier.class;
      return this;
    }

    public Builder signingThreshold(int signingThreshold) {
      if (signingThreshold < 1) {
        throw new IllegalArgumentException("signingThreshold must be 1 or greater");
      }

      this.signingThreshold = SigningThresholds.unweighted(signingThreshold);
      return this;
    }

    public Builder signingThreshold(SigningThreshold signingThreshold) {
      this.signingThreshold = requireNonNull(signingThreshold);
      return this;
    }

    public Builder format(Format format) {
      this.format = requireNonNull(format);
      return this;
    }

    public Builder key(PublicKey key) {
      this.keys.add(requireNonNull(key));
      return this;
    }

    public Builder keys(List<PublicKey> keys) {
      requireNonNull(keys);

      if (keys.isEmpty()) {
        throw new RuntimeException("Public keys must be provided.");
      }

      this.keys.addAll(keys);
      return this;
    }

    public Builder signer(Signer signer) {
      this.signer = signer;
      return this;
    }

    public Builder signer(int keyIndex, PrivateKey privateKey) {
      if (keyIndex < 0) {
        throw new IllegalArgumentException("keyIndex must be >= 0");
      }

      this.signer = new PrivateKeySigner(keyIndex, requireNonNull(privateKey));
      return this;
    }

    public Builder nextSigningThreshold(int nextSigningThreshold) {
      if (nextSigningThreshold < 1) {
        throw new IllegalArgumentException("nextSigningThreshold must be 1 or greater");
      }

      this.nextSigningThreshold = SigningThresholds.unweighted(nextSigningThreshold);

      return this;
    }

    public Builder nextSigningThreshold(SigningThreshold nextSigningThreshold) {
      this.nextSigningThreshold = requireNonNull(nextSigningThreshold);
      return this;
    }

    public Builder nextKeys(KeyConfigurationDigest nextKeysDigest) {
      this.nextKeyConfigurationDigest = requireNonNull(nextKeysDigest);
      return this;
    }

    public Builder witness(BasicIdentifier witness) {
      this.witnesses.add(requireNonNull(witness));
      return this;
    }

    public Builder witnesses(List<BasicIdentifier> witnesses) {
      this.witnesses.addAll(requireNonNull(witnesses));
      return this;
    }

    public Builder witnessThreshold(int witnessThreshold) {
      if (witnessThreshold < 1) {
        throw new IllegalArgumentException("witnessThreshold must be 1 or greater");
      }

      this.witnessThreshold = witnessThreshold;
      return this;
    }

    public Builder configurationTraits(ConfigurationTrait... configurationTraits) {
      Collections.addAll(this.configurationTraits, configurationTraits);
      return this;
    }

    public Builder establishmentEventsOnly() {
      this.configurationTraits.add(ConfigurationTrait.ESTABLISHMENT_EVENTS_ONLY);
      return this;
    }

    public Builder doNotDelegate() {
      this.configurationTraits.add(ConfigurationTrait.DO_NOT_DELEGATE);
      return this;
    }

    public IdentifierSpec build() {

      // --- KEYS ---

      if (this.keys.isEmpty()) {
        throw new RuntimeException("No keys provided.");
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
        var countOfWeights = Stream.of(w.weights())
            .mapToLong(wts -> wts.length)
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
          var countOfWeights = Stream.of(w.weights())
              .mapToLong(wts -> wts.length)
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

      if ((this.witnessThreshold == 0) && !this.witnesses.isEmpty()) {
        this.witnessThreshold = (this.witnesses.size() / 2) + 1;
      }

      if (!this.witnesses.isEmpty()
          && ((this.witnessThreshold < 1) || (this.witnessThreshold > this.witnesses.size()))) {
        throw new RuntimeException(
            "Invalid witness threshold:"
                + " witnesses: " + this.witnesses.size()
                + " threshold: " + this.witnessThreshold);
      }

      // TODO test duplicate detection--need to write equals() hashcode for classes
      if (this.witnesses.size() != Set.copyOf(this.witnesses).size()) {
        throw new RuntimeException("List of witnesses has duplicates");
      }

      // validation is provided by spec consumer
      return new IdentifierSpec(
          this.derivation,
          this.selfAddressingDigestAlgorithm,
          this.format,
          this.signingThreshold,
          this.keys,
          this.signer,
          this.nextKeyConfigurationDigest,
          this.witnessThreshold,
          this.witnesses,
          this.configurationTraits);
    }

  }

}
