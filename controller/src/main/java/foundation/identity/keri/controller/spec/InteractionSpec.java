package foundation.identity.keri.controller.spec;

import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.crypto.StandardFormats;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.internal.event.ImmutableIdentifierEventCoordinatesWithDigest;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

public class InteractionSpec {

  private final Format format;

  private final Identifier identifier;
  private final BigInteger sequenceNumber;
  private final IdentifierEventCoordinatesWithDigest previous;

  private final Signer signer;

  private final List<Seal> seals;

  public InteractionSpec(Format format, Identifier identifier, BigInteger sequenceNumber, IdentifierEventCoordinatesWithDigest previous,
                         Signer signer, List<Seal> seals) {
    this.format = format;
    this.identifier = identifier;
    this.sequenceNumber = sequenceNumber;
    this.previous = previous;
    this.signer = signer;
    this.seals = seals;
  }

  public static Builder builder(IdentifierState state) {
    return new Builder(state);
  }

  public Format format() {
    return this.format;
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

  public Signer signer() {
    return this.signer;
  }

  public List<Seal> seals() {
    return this.seals;
  }

  public static class Builder {
    private final IdentifierState state;
    private final List<Seal> seals = new ArrayList<>();
    private Format format = StandardFormats.JSON;
    private Signer signer;

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

    public InteractionSpec build() {
      return new InteractionSpec(
          this.format,
          this.state.identifier(),
          this.state.lastEvent().sequenceNumber().add(BigInteger.ONE),
          ImmutableIdentifierEventCoordinatesWithDigest.of(this.state.lastEvent()),
          this.signer,
          this.seals);
    }

  }

}
