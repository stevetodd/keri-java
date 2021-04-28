package foundation.identity.keri;

import foundation.identity.keri.api.event.KeyEvent;

public class UnmetWitnessThresholdException extends KeyEventProcessingException {

  public UnmetWitnessThresholdException(KeyEvent keyEvent) {
    super(keyEvent);
  }

}
