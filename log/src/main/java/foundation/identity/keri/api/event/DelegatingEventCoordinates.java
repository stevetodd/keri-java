package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.Identifier;

public interface DelegatingEventCoordinates {

  Identifier identifier();

  long sequenceNumber();

  KeyEventCoordinates previousEvent();

}
