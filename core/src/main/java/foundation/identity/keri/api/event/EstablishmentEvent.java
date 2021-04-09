package foundation.identity.keri.api.event;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

public interface EstablishmentEvent extends KeyEvent {

  SigningThreshold signingThreshold();

  List<PublicKey> keys();

  Optional<KeyConfigurationDigest> nextKeyConfiguration();

  int witnessThreshold();

}
