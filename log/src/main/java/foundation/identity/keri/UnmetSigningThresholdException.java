package foundation.identity.keri;

import foundation.identity.keri.api.event.KeyEvent;

public class UnmetSigningThresholdException extends KeyEventProcessingException {

  public UnmetSigningThresholdException(KeyEvent keyEvent) {
    super(keyEvent);
  }

}
