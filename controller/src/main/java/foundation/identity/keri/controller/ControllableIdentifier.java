package foundation.identity.keri.controller;

import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.seal.Seal;

import java.util.List;

public interface ControllableIdentifier extends KeyState {

  void rotate();

  void rotate(List<Seal> seals);

  void seal(List<Seal> seals);

  EventSignature sign(KeyEvent event);

}
