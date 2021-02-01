package foundation.identity.keri.internal.event;

import foundation.identity.keri.QualifiedBase64;
import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.EventSignatureCoordinates;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyCoordinates;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Objects;

public class ImmutableEventSignatureCoordinates implements EventSignatureCoordinates {

  private final Identifier identifier;
  private final BigInteger sequenceNumber;
  private final Digest digest;
  private final int index;

  public ImmutableEventSignatureCoordinates(Identifier identifier, BigInteger sequenceNumber, Digest digest, int index) {
    this.identifier = identifier;
    this.sequenceNumber = sequenceNumber;
    this.digest = digest;
    this.index = index;
  }

  public static ImmutableEventSignatureCoordinates of(IdentifierEventCoordinatesWithDigest eventCoordinates,
                                                      KeyCoordinates keyCoordinates) {
    return new ImmutableEventSignatureCoordinates(
        eventCoordinates.identifier(),
        eventCoordinates.sequenceNumber(),
        eventCoordinates.digest(),
        keyCoordinates.index()
    );
  }

  public static ImmutableEventSignatureCoordinates of(EventSignature eventSignature) {
    return new ImmutableEventSignatureCoordinates(
        eventSignature.event().identifier(),
        eventSignature.event().sequenceNumber(),
        eventSignature.event().digest(),
        eventSignature.key().index());
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
  public int index() {
    return this.index;
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.digest, this.identifier, this.index, this.sequenceNumber);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof ImmutableEventSignatureCoordinates)) {
      return false;
    }

    var other = (ImmutableEventSignatureCoordinates) obj;
    return Objects.equals(this.digest, other.digest)
        && Objects.equals(this.identifier, other.identifier)
        && (this.index == other.index)
        && Objects.equals(this.sequenceNumber, other.sequenceNumber);
  }

  @Override
  public String toString() {
    return String.join(":",
        QualifiedBase64.qb64(this.identifier),
        this.sequenceNumber.toString(),
        QualifiedBase64.qb64(this.digest),
        Integer.toString(this.index)
    );
  }

}
