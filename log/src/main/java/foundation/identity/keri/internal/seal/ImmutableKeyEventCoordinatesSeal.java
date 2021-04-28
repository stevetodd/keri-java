package foundation.identity.keri.internal.seal;

import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.seal.KeyEventCoordinatesSeal;

public class ImmutableKeyEventCoordinatesSeal implements KeyEventCoordinatesSeal {

  private final KeyEventCoordinates event;

  public ImmutableKeyEventCoordinatesSeal(KeyEventCoordinates event) {
    this.event = event;
  }

  @Override
  public KeyEventCoordinates event() {
    return this.event;
  }


}
