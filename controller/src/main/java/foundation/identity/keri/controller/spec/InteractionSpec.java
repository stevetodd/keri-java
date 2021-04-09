package foundation.identity.keri.controller.spec;

import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.crypto.StandardFormats;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.internal.event.ImmutableKeyEventCoordinates;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

public class InteractionSpec {

  private final Format format;

  private final Identifier identifier;
  private final long sequenceNumber;
  private final KeyEventCoordinates previous;

  private final Signer signer;

  private final List<Seal> seals;

  public InteractionSpec(Format format, Identifier identifier, long sequenceNumber, KeyEventCoordinates previous,
                         Signer signer, List<Seal> seals) {
    this.format = format;
    this.identifier = identifier;
    this.sequenceNumber = sequenceNumber;
    this.previous = previous;
    this.signer = signer;
    this.seals = List.copyOf(seals);
  }

  public static Builder builder(KeyState state) {
    return new Builder(state);
  }

  public Format format() {
    return this.format;
  }

  public Identifier identifier() {
    return this.identifier;
  }

  public long sequenceNumber() {
    return this.sequenceNumber;
  }

  public KeyEventCoordinates previous() {
    return this.previous;
  }

  public Signer signer() {
    return this.signer;
  }

  public List<Seal> seals() {
    return this.seals;
  }

  public static class Builder {
    private final KeyState state;
    private final List<Seal> seals = new ArrayList<>();
    private Format format = StandardFormats.JSON;
    private Signer signer;

    public Builder(KeyState state) {
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
      this.signer = requireNonNull(signer);
      return this;
    }

    public Builder signer(int keyIndex, PrivateKey privateKey) {
      if (keyIndex < 0) {
        throw new IllegalArgumentException("keyIndex must be >= 0");
      }

      this.signer = new PrivateKeySigner(keyIndex, requireNonNull(privateKey));
      return this;
    }

    public Builder seal(Seal seal) {
      this.seals.add(requireNonNull(seal));
      return this;
    }

    public Builder seals(List<Seal> seals) {
      this.seals.addAll(requireNonNull(seals));
      return this;
    }

    public InteractionSpec build() {
      return new InteractionSpec(
          this.format,
          this.state.identifier(),
          this.state.lastEvent().sequenceNumber() + 1,
          ImmutableKeyEventCoordinates.of(this.state.lastEvent()),
          this.signer,
          this.seals);
    }

  }

}
