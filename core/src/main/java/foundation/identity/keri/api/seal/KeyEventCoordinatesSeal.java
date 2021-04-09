package foundation.identity.keri.api.seal;

import foundation.identity.keri.api.event.KeyEventCoordinates;

public interface KeyEventCoordinatesSeal extends Seal {

  KeyEventCoordinates event();

}
