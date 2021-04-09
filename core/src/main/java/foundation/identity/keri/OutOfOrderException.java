package foundation.identity.keri;

import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;

public class OutOfOrderException extends RuntimeException {

  private final Event event;
  private final IdentifierEventCoordinatesWithDigest requiredEvent;
  private final DelegatingEventCoordinates requiredDelegatingEvent;

  public OutOfOrderException(Event event, IdentifierEventCoordinatesWithDigest requiredEvent) {
    this.event = event;
    this.requiredEvent = requiredEvent;
    this.requiredDelegatingEvent = null;
  }

  public OutOfOrderException(IdentifierEvent event, DelegatingEventCoordinates delegatingEvent) {
    this.event = event;
    this.requiredEvent = null;
    this.requiredDelegatingEvent = delegatingEvent;
  }

  public Event event() {
    return this.event;
  }

  public IdentifierEventCoordinatesWithDigest requiredEvent() {
    return this.requiredEvent;
  }

  public DelegatingEventCoordinates requiredDelegatingEvent() {
    return this.requiredDelegatingEvent;
  }

}
