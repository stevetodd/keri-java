package foundation.identity.keri.api.event;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;

public interface KeyCoordinates {

  IdentifierEventCoordinatesWithDigest establishmentEvent();

  int keyIndex();

}
