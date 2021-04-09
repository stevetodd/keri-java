package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.KeyCoordinates;
import foundation.identity.keri.api.identifier.BasicIdentifier;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

public class ImmutableKeyCoordinates implements KeyCoordinates {

  private final int keyIndex;
  private final KeyEventCoordinates establishmentEvent;

  public ImmutableKeyCoordinates(KeyEventCoordinates establishmentEvent, int keyIndex) {
    if (keyIndex < 0) {
      throw new IllegalArgumentException("keyIndex must be >= 0");
    }

    this.establishmentEvent = requireNonNull(establishmentEvent, "establishmentEvent");
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
    var coordinates = ImmutableKeyEventCoordinates.of(basicIdentifier);
    return new ImmutableKeyCoordinates(coordinates, 0);
  }

  public static ImmutableKeyCoordinates of(EstablishmentEvent establishmentEvent, int keyIndex) {
    var coordinates = ImmutableKeyEventCoordinates.of(establishmentEvent);
    return new ImmutableKeyCoordinates(coordinates, keyIndex);
  }

  @Override
  public KeyEventCoordinates establishmentEvent() {
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

    var that = (KeyCoordinates) o;
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
