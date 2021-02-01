package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.seal.Seal;

import java.util.List;

public interface RotationEvent extends EstablishmentEvent {

  List<BasicIdentifier> removedWitnesses();

  List<BasicIdentifier> addedWitnesses();

  List<Seal> seals();

  @Override
  default EventType type() {
    return EventType.ROTATION;
  }

}
