package foundation.identity.keri.api.event;

import foundation.identity.keri.api.seal.Seal;

import java.util.List;

public interface InteractionEvent extends IdentifierEvent {

  List<Seal> seals();

  @Override
  default EventType type() {
    return EventType.INTERACTION;
  }

}
