package foundation.identity.keri;

import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;

public class MissingEventException extends RuntimeException {

  private final IdentifierEventCoordinatesWithDigest missingEvent;
  private final Event dependingEvent;

  public MissingEventException(IdentifierEventCoordinatesWithDigest missingEvent,
      Event dependingEvent) {
    this.missingEvent = missingEvent;
    this.dependingEvent = dependingEvent;
  }

  public IdentifierEventCoordinatesWithDigest missingEvent() {
    return this.missingEvent;
  }

  public Event dependingEvent() {
    return this.dependingEvent;
  }

}
