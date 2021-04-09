package foundation.identity.keri.api.event;

import foundation.identity.keri.api.Version;

public interface Event {

  byte[] bytes();

  Version version();

  Format format();

}
