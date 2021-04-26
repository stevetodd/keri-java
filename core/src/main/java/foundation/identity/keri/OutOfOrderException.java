package foundation.identity.keri;

import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;

public class OutOfOrderException extends RuntimeException {

  private final KeyEvent event;
  private final KeyEventCoordinates requiredEvent;
  private final DelegatingEventCoordinates requiredDelegatingEvent;

  public OutOfOrderException(KeyEvent event, KeyEventCoordinates requiredEvent) {
    this.event = event;
    this.requiredEvent = requiredEvent;
    this.requiredDelegatingEvent = null;
  }

  public OutOfOrderException(KeyEvent event, DelegatingEventCoordinates delegatingEvent) {
    this.event = event;
    this.requiredEvent = null;
    this.requiredDelegatingEvent = delegatingEvent;
  }

  public KeyEvent event() {
    return this.event;
  }

  public KeyEventCoordinates requiredEvent() {
    return this.requiredEvent;
  }

  public DelegatingEventCoordinates requiredDelegatingEvent() {
    return this.requiredDelegatingEvent;
  }

}
