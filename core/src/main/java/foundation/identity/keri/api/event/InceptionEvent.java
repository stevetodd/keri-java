package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.BasicIdentifier;

import java.util.List;
import java.util.Set;

public interface InceptionEvent extends EstablishmentEvent {

  byte[] inceptionStatement();

  List<BasicIdentifier> witnesses();

  Set<ConfigurationTrait> configurationTraits();

  @Override
  default EventType type() {
    return EventType.INCEPTION;
  }

}
