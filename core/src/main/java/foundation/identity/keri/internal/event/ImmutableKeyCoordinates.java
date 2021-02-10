package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyCoordinates;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Objects;

import static foundation.identity.keri.QualifiedBase64.qb64;
import static java.util.Objects.requireNonNull;

public class ImmutableKeyCoordinates implements KeyCoordinates {

  private final int keyIndex;
  private final IdentifierEventCoordinatesWithDigest establishmentEvent;

  public ImmutableKeyCoordinates(IdentifierEventCoordinatesWithDigest establishmentEvent, int keyIndex) {
    if (keyIndex < 0) {
      throw new IllegalArgumentException("keyIndex must be >= 0");
    }

    this.establishmentEvent = requireNonNull(establishmentEvent);
    this.keyIndex = keyIndex;
  }

  public static ImmutableKeyCoordinates convert(KeyCoordinates coordinates) {
    if (coordinates instanceof ImmutableKeyCoordinates) {
      return (ImmutableKeyCoordinates) coordinates;
    }

    return new ImmutableKeyCoordinates(
        coordinates.establishmentEvent(),
        coordinates.keyIndex()
    );
  }

  public static ImmutableKeyCoordinates of(BasicIdentifier basicIdentifier) {
    var coordinates = ImmutableIdentifierEventCoordinatesWithDigest.of(basicIdentifier);
    return new ImmutableKeyCoordinates(coordinates, 0);
  }

  public static ImmutableKeyCoordinates of(EstablishmentEvent establishmentEvent, int keyIndex) {
    var coordinates = ImmutableIdentifierEventCoordinatesWithDigest.of(establishmentEvent);
    return new ImmutableKeyCoordinates(coordinates, keyIndex);
  }

  @Override
  public IdentifierEventCoordinatesWithDigest establishmentEvent() {
    return this.establishmentEvent;
  }

  @Override
  public int keyIndex() {
    return this.keyIndex;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (!(o instanceof KeyCoordinates)) {
      return false;
    }

    KeyCoordinates that = (KeyCoordinates) o;
    return Objects.equals(this.establishmentEvent, that.establishmentEvent())
        && this.keyIndex == that.keyIndex();
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.establishmentEvent, this.keyIndex);
  }

  @Override
  public String toString() {
    return this.establishmentEvent + ":" + this.keyIndex;
  }
}
