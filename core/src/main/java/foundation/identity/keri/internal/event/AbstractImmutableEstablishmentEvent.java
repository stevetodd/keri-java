package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

public abstract class AbstractImmutableEstablishmentEvent extends AbstractImmutableIdentifierEvent implements EstablishmentEvent {

  final SigningThreshold signingThreshold;

  final List<PublicKey> keys;

  final Optional<KeyConfigurationDigest> nextKeys;

  final int witnessThreshold;

  public AbstractImmutableEstablishmentEvent(
      Version version,
      Format format,
      Identifier identifier,
      BigInteger sequenceNumber,
      IdentifierEventCoordinatesWithDigest previous,
      SigningThreshold signingThreshold,
      List<PublicKey> keys,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
      byte[] bytes,
      Set<EventSignature> signatures) {
    super(version, format, identifier, sequenceNumber, previous, bytes, signatures);
    requireNonNull(keys);

    this.signingThreshold = signingThreshold;
    this.keys = List.copyOf(keys);
    this.nextKeys = Optional.ofNullable(nextKeys);
    this.witnessThreshold = witnessThreshold;
  }

  @Override
  public SigningThreshold signingThreshold() {
    return this.signingThreshold;
  }

  @Override
  public List<PublicKey> keys() {
    return this.keys;
  }

  @Override
  public Optional<KeyConfigurationDigest> nextKeyConfiguration() {
    return this.nextKeys;
  }

  @Override
  public int witnessThreshold() {
    return this.witnessThreshold;
  }

}
