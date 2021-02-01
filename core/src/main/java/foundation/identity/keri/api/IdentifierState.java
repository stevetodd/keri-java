package foundation.identity.keri.api;

import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface IdentifierState {

  Identifier identifier();

  int signingThreshold();

  List<PublicKey> keys();

  Optional<KeyConfigurationDigest> nextKeyConfigurationDigest();

  default boolean transferrable() {
    return identifier().transferable()
        && nextKeyConfigurationDigest().isPresent();
  }

  int witnessThreshold();

  List<BasicIdentifier> witnesses();

  Set<ConfigurationTrait> configurationTraits();

  IdentifierEvent lastEvent();

  EstablishmentEvent lastEstablishmentEvent();

  Optional<Identifier> delegatingIdentifier();

  default boolean delegated() {
    return delegatingIdentifier().isPresent();
  }

}
