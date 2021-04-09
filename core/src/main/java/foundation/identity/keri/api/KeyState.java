package foundation.identity.keri.api;

import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface KeyState {

  Identifier identifier();

  SigningThreshold signingThreshold();

  List<PublicKey> keys();

  Optional<KeyConfigurationDigest> nextKeyConfigurationDigest();

  default boolean transferable() {
    return identifier().transferable()
        && nextKeyConfigurationDigest().isPresent();
  }

  int witnessThreshold();

  List<BasicIdentifier> witnesses();

  Set<ConfigurationTrait> configurationTraits();

  KeyEvent lastEvent();

  EstablishmentEvent lastEstablishmentEvent();

  Optional<Identifier> delegatingIdentifier();

  default boolean delegated() {
    return delegatingIdentifier().isPresent();
  }

}
