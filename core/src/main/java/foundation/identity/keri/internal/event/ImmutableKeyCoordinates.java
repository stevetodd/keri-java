package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyCoordinates;

public class ImmutableKeyCoordinates extends ImmutableIdentifierEventCoordinatesWithDigest implements KeyCoordinates {

  private final int keyIndex;

  public ImmutableKeyCoordinates(IdentifierEventCoordinatesWithDigest coordinates, int keyIndex) {
    super(coordinates);
    this.keyIndex = keyIndex;
  }

  public ImmutableKeyCoordinates(KeyCoordinates coordinates) {
    super(coordinates);
    this.keyIndex = coordinates.index();
  }

  public static ImmutableKeyCoordinates of(EstablishmentEvent event, int keyIndex) {
    var coordinates = ImmutableIdentifierEventCoordinatesWithDigest.of(event);
    return new ImmutableKeyCoordinates(coordinates, 0);
  }

  public static ImmutableKeyCoordinates of(IdentifierEventCoordinatesWithDigest coords, int keyIndex) {
    return new ImmutableKeyCoordinates(coords, 0);
  }

  @Override
  public int index() {
    return this.keyIndex;
  }

}
