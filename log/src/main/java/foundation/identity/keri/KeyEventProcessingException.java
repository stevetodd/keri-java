package foundation.identity.keri;

import foundation.identity.keri.api.event.KeyEvent;

public abstract class KeyEventProcessingException extends RuntimeException {

  private final KeyEvent keyEvent;

  public KeyEventProcessingException(KeyEvent keyEvent) {
    this.keyEvent = keyEvent;
  }

  public KeyEvent keyEvent() {
    return this.keyEvent;
  }

}
