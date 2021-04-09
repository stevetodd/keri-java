package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;

public interface DelegatingEventCoordinates {

  Identifier identifier();

  BigInteger sequenceNumber();

  EventType eventType();

  KeyEventCoordinates previousEvent();

}
