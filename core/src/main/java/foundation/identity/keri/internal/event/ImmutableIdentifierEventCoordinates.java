package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinates;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Objects;

public class ImmutableIdentifierEventCoordinates implements IdentifierEventCoordinates {

  private final Identifier identifier;
  private final BigInteger sequenceNumber;

  public ImmutableIdentifierEventCoordinates(Identifier identifier, BigInteger sequenceNumber) {
    this.identifier = identifier;
    this.sequenceNumber = sequenceNumber;
  }

  public ImmutableIdentifierEventCoordinates(IdentifierEventCoordinates coordinates) {
    this.identifier = coordinates.identifier();
    this.sequenceNumber = coordinates.sequenceNumber();
  }

  public static ImmutableIdentifierEventCoordinates of(IdentifierEvent e) {
    return new ImmutableIdentifierEventCoordinates(e.identifier(), e.sequenceNumber());
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
  public int hashCode() {
    return Objects.hash(this.identifier, this.sequenceNumber);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (obj == null) {
      return false;
    }
    if (!(obj instanceof ImmutableIdentifierEventCoordinates)) {
      return false;
    }

    var other = (ImmutableIdentifierEventCoordinates) obj;
    return Objects.equals(this.identifier, other.identifier)
        && Objects.equals(this.sequenceNumber, other.sequenceNumber);
  }

}
