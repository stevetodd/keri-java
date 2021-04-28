package foundation.identity.keri;

import foundation.identity.keri.api.event.KeyCoordinates;

import java.security.KeyPair;
import java.util.Optional;

public interface IdentifierKeyStore {

  void storeKey(KeyCoordinates keyCoordinates, KeyPair keyPair);

  Optional<KeyPair> getKey(KeyCoordinates keyCoordinates);

  Optional<KeyPair> removeKey(KeyCoordinates keyCoordinates);

  void storeNextKey(KeyCoordinates keyCoordinates, KeyPair keyPair);

  Optional<KeyPair> getNextKey(KeyCoordinates keyCoordinates);

  Optional<KeyPair> removeNextKey(KeyCoordinates keyCoordinates);

}
