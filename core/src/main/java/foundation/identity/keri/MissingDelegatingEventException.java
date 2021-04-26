package foundation.identity.keri;

import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.KeyEvent;

public class MissingDelegatingEventException extends KeyEventProcessingException {

  private final DelegatingEventCoordinates missingEvent;

  public MissingDelegatingEventException(KeyEvent dependingEvent,
      DelegatingEventCoordinates missingEvent) {
    super(dependingEvent);
    this.missingEvent = missingEvent;
  }

  public DelegatingEventCoordinates missingEvent() {
    return this.missingEvent;
  }

}
