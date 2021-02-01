package foundation.identity.keri.controller;

import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.seal.Seal;

import java.util.List;

public interface ControllableIdentifier extends IdentifierState {

  void rotate();

  void rotate(List<Seal> seals);

  void seal(List<Seal> seals);

  EventSignature sign(IdentifierEvent event);

}
