package foundation.identity.keri.internal.seal;

import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.seal.EventCoordinatesWithDigestSeal;

public class ImmutableIdentifierEventCoordinatesWithDigestSeal implements EventCoordinatesWithDigestSeal {

  private final IdentifierEventCoordinatesWithDigest event;

  public ImmutableIdentifierEventCoordinatesWithDigestSeal(IdentifierEventCoordinatesWithDigest event) {
    this.event = event;
  }

  @Override
  public IdentifierEventCoordinatesWithDigest event() {
    return this.event;
  }


}
