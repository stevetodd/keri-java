package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.EventSignatureCoordinates;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyCoordinates;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Objects;

import static foundation.identity.keri.QualifiedBase64.qb64;
import static java.util.Objects.requireNonNull;

public class ImmutableEventSignatureCoordinates implements EventSignatureCoordinates {

  private final Identifier identifier;
  private final BigInteger sequenceNumber;
  private final Digest digest;
  private final int keyIndex;

  public ImmutableEventSignatureCoordinates(Identifier identifier, BigInteger sequenceNumber, Digest digest, int keyIndex) {
    if (sequenceNumber.compareTo(BigInteger.ZERO) < 0) {
      throw new IllegalArgumentException("sequenceNumber must be >= 0");
    }

    if (keyIndex < 0) {
      throw new IllegalArgumentException("keyIndex must be >= 0");
    }

    this.identifier = requireNonNull(identifier, "identifier");
    this.sequenceNumber = requireNonNull(sequenceNumber, "sequenceNumber");
    this.digest = requireNonNull(digest, "digest");
    this.keyIndex = requireNonNull(keyIndex, "keyIndex");
  }

  public static ImmutableEventSignatureCoordinates of(IdentifierEventCoordinatesWithDigest event,
                                                      KeyCoordinates key) {
    return new ImmutableEventSignatureCoordinates(
        event.identifier(),
        event.sequenceNumber(),
        event.digest(),
        key.keyIndex()
    );
  }

  public static ImmutableEventSignatureCoordinates of(EventSignature eventSignature) {
    return new ImmutableEventSignatureCoordinates(
        eventSignature.event().identifier(),
        eventSignature.event().sequenceNumber(),
        eventSignature.event().digest(),
        eventSignature.key().keyIndex());
  }

  @Override
  public Identifier identifier() {
    return this.identifier;
  }

  @Override
  public BigInteger sequenceNumber() {
    return this.sequenceNumber;
  }

  @Override
  public Digest digest() {
    return this.digest;
  }

  @Override
  public int keyIndex() {
    return this.keyIndex;
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.digest, this.identifier, this.keyIndex, this.sequenceNumber);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof EventSignatureCoordinates)) {
      return false;
    }

    var other = (EventSignatureCoordinates) obj;
    return Objects.equals(this.digest, other.digest())
        && Objects.equals(this.identifier, other.identifier())
        && (this.keyIndex == other.keyIndex())
        && Objects.equals(this.sequenceNumber, other.sequenceNumber());
  }

  @Override
  public String toString() {
    return String.join(":",
        qb64(this.identifier),
        this.sequenceNumber.toString(),
        qb64(this.digest),
        Integer.toString(this.keyIndex)
    );
  }

}
