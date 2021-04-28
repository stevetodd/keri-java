package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.seal.Seal;

import java.util.List;

public interface RotationEvent extends EstablishmentEvent, SealingEvent {

  List<BasicIdentifier> removedWitnesses();

  List<BasicIdentifier> addedWitnesses();

  List<Seal> seals();

}
