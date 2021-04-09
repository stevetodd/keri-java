package foundation.identity.keri;

import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.KeyEventCoordinates;

public class MissingEventException extends RuntimeException {

  private final KeyEventCoordinates missingEvent;
  private final Event dependingEvent;

  public MissingEventException(KeyEventCoordinates missingEvent,
      Event dependingEvent) {
    this.missingEvent = missingEvent;
    this.dependingEvent = dependingEvent;
  }

  public KeyEventCoordinates missingEvent() {
    return this.missingEvent;
  }

  public Event dependingEvent() {
    return this.dependingEvent;
  }

}
