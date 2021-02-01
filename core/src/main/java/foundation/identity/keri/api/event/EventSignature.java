package foundation.identity.keri.api.event;

import foundation.identity.keri.api.crypto.Signature;

public interface EventSignature {

  IdentifierEventCoordinatesWithDigest event();

  KeyCoordinates key();

  Signature signature();

}
