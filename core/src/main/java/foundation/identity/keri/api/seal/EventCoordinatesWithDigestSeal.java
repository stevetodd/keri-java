package foundation.identity.keri.api.seal;

import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;

public interface EventCoordinatesWithDigestSeal extends Seal {

  IdentifierEventCoordinatesWithDigest event();

}
