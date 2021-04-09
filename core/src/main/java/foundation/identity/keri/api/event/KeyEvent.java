package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.Identifier;

import java.util.Set;

public interface KeyEvent extends Event {

  Identifier identifier();

  long sequenceNumber();

  KeyEventCoordinates coordinates();

  KeyEventCoordinates previous();

  Set<AttachedEventSignature> signatures();

}
