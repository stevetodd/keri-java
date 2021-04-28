package foundation.identity.keri.api.event;

import foundation.identity.keri.api.seal.Seal;

import java.util.List;

public interface SealingEvent extends KeyEvent {

  List<Seal> seals();

}
