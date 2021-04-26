package foundation.identity.keri.api;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface KeyState {

  default Identifier identifier() {
    return this.coordinates().identifier();
  }

  default long sequenceNumber() {
    return this.coordinates().sequenceNumber();
  }

  default Digest digest() {
    return this.coordinates().digest();
  }

  KeyEventCoordinates coordinates();

  SigningThreshold signingThreshold();

  List<PublicKey> keys();

  Optional<KeyConfigurationDigest> nextKeyConfigurationDigest();

  default boolean transferable() {
    return this.coordinates().identifier().transferable()
        && this.nextKeyConfigurationDigest().isPresent();
  }

  int witnessThreshold();

  List<BasicIdentifier> witnesses();

  Set<ConfigurationTrait> configurationTraits();

  KeyEvent lastEvent();

  EstablishmentEvent lastEstablishmentEvent();

  Optional<Identifier> delegatingIdentifier();

  default boolean delegated() {
    return this.delegatingIdentifier().isPresent();
  }

}
