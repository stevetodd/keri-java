package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Set;

public interface KeyEvent extends Event {

  Identifier identifier();

  BigInteger sequenceNumber();

  KeyEventCoordinates coordinates();

  KeyEventCoordinates previous();

  Set<AttachedEventSignature> signatures();

}
