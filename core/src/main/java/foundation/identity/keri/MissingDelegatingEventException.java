package foundation.identity.keri;

import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.Event;

public class MissingDelegatingEventException extends RuntimeException {

  private final DelegatingEventCoordinates missingEvent;
  private final Event dependingEvent;

  public MissingDelegatingEventException(DelegatingEventCoordinates missingEvent,
      Event dependingEvent) {
    this.missingEvent = missingEvent;
    this.dependingEvent = dependingEvent;
  }

  public DelegatingEventCoordinates missingEvent() {
    return this.missingEvent;
  }

  public Event dependingEvent() {
    return this.dependingEvent;
  }

}
