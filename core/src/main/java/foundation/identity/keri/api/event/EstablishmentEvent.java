package foundation.identity.keri.api.event;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

public interface EstablishmentEvent extends IdentifierEvent {

  int signingThreshold();

  List<PublicKey> keys();

  Optional<KeyConfigurationDigest> nextKeyConfiguration();

  int witnessThreshold();

}
