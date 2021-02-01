package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Set;

public interface IdentifierEvent extends Event {

  Identifier identifier();

  BigInteger sequenceNumber();

  IdentifierEventCoordinatesWithDigest previous();

  Set<EventSignature> signatures();

}
