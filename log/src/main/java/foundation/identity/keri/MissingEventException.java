package foundation.identity.keri;

import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;

public class MissingEventException extends KeyEventProcessingException {

  private final KeyEventCoordinates missingEvent;

  public MissingEventException(KeyEvent dependingEvent, KeyEventCoordinates missingEvent) {
    super(dependingEvent);
    this.missingEvent = missingEvent;
  }

  public KeyEventCoordinates missingEvent() {
    return this.missingEvent;
  }

}
