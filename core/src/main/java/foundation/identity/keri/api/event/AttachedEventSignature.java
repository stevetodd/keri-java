package foundation.identity.keri.api.event;

import foundation.identity.keri.api.crypto.Signature;

public interface AttachedEventSignature {

  IdentifierEventCoordinatesWithDigest event();

  int keyIndex();

  Signature signature();

}