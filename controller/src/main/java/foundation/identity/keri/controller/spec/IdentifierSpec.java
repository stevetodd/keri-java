package foundation.identity.keri.controller.spec;

import foundation.identity.keri.KeyConfigurationDigester;
import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.api.crypto.StandardDigestAlgorithms;
import foundation.identity.keri.api.crypto.StandardFormats;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;
import foundation.identity.keri.api.identifier.SelfSigningIdentifier;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

public class IdentifierSpec {

  private final Class<? extends Identifier> derivation;
  private final DigestAlgorithm identifierDigestAlgorithm;

  private final Format format;

  private final int signingThreshold;

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
      int signingThreshold,
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

  public List<BasicIdentifier> witnesses() {
    return this.witnesses;
  }

  public Set<ConfigurationTrait> configurationTraits() {
    return this.configurationTraits;
  }

  public static class Builder {

    private final List<PublicKey> keys = new ArrayList<>();
    private final List<Digest> nextKeyDigests = new ArrayList<>();
    private final List<PublicKey> nextKeys = new ArrayList<>();
    private final List<BasicIdentifier> witnesses = new ArrayList<>();
    private final EnumSet<ConfigurationTrait> configurationTraits = EnumSet.noneOf(ConfigurationTrait.class);
    private final DigestAlgorithm nextKeysAlgorithm = StandardDigestAlgorithms.BLAKE3_256;
    private Class<? extends Identifier> derivation = SelfAddressingIdentifier.class;
    private DigestAlgorithm selfAddressingDigestAlgorithm = StandardDigestAlgorithms.BLAKE3_256;
    private Format format = StandardFormats.JSON;
    private int signingThreshold = 0;
    private Signer signer;
    private KeyConfigurationDigest nextKeysDigest = KeyConfigurationDigest.NONE;
    private int nextSigningThreshold = 0;
    private int witnessThreshold = 0;

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

      this.signingThreshold = signingThreshold;
      return this;
    }

    public Builder format(Format format) {
      requireNonNull(format);

      this.format = format;

      return this;
    }

    public Builder key(PublicKey key) {
      requireNonNull(key);

      this.keys.add(key);

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

    public Builder witness(BasicIdentifier witness) {
      requireNonNull(witness);

      this.witnesses.add(witness);

      return this;
    }

    public Builder witnesses(List<BasicIdentifier> witnesses) {
      requireNonNull(witnesses);

      this.witnesses.addAll(witnesses);

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
      this.configurationTraits.addAll(List.of(configurationTraits));
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
          this.nextKeysDigest,
          this.witnessThreshold,
          this.witnesses,
          this.configurationTraits);
    }

  }

}
