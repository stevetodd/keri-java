package foundation.identity.keri;

import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.IdentifierEvent;

public interface EventStore extends EventSource {

  void store(IdentifierEvent event);

  void store(EventSignature signature);

}