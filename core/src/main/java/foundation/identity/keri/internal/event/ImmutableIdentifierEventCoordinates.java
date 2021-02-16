package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinates;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

public class ImmutableIdentifierEventCoordinates implements IdentifierEventCoordinates {

  private final Identifier identifier;
  private final BigInteger sequenceNumber;

  public ImmutableIdentifierEventCoordinates(Identifier identifier, BigInteger sequenceNumber) {
    if (sequenceNumber.compareTo(BigInteger.ZERO) < 0) {
      throw new IllegalArgumentException("sequenceNumber must be >= 0");
    }

    this.identifier = requireNonNull(identifier);
    this.sequenceNumber = requireNonNull(sequenceNumber);
  }

  public static ImmutableIdentifierEventCoordinates convert(IdentifierEventCoordinates coordinates) {
    if (coordinates instanceof ImmutableIdentifierEventCoordinates) {
      return (ImmutableIdentifierEventCoordinates) coordinates;
    }

    return new ImmutableIdentifierEventCoordinates(
        coordinates.identifier(),
        coordinates.sequenceNumber()
    );
  }

  public static ImmutableIdentifierEventCoordinates of(IdentifierEvent e) {
    requireNonNull(e);
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
    if (!(obj instanceof IdentifierEventCoordinates)) {
      return false;
    }

    var other = (IdentifierEventCoordinates) obj;
    return Objects.equals(this.identifier, other.identifier())
        && Objects.equals(this.sequenceNumber, other.sequenceNumber());
  }

  @Override
  public String toString() {
    return this.identifier + ":" + this.sequenceNumber;
  }
}
