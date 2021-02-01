package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.DelegatedRotationEvent;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

public final class ImmutableDelegatedRotationEvent extends AbstractImmutableDelegatedEstablishmentEvent
    implements DelegatedRotationEvent {

  private final List<BasicIdentifier> addedWitnesses;

  private final List<BasicIdentifier> removedWitnesses;

  private final List<Seal> seals;

  public ImmutableDelegatedRotationEvent(
      Version version,
      Format format,
      Identifier identifier,
      BigInteger sequenceNumber,
      IdentifierEventCoordinatesWithDigest previous,
      int signingThreshold,
      List<PublicKey> keys,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
      List<BasicIdentifier> removedWitnesses,
      List<BasicIdentifier> addedWitnesses,
      List<Seal> seals,
      DelegatingEventCoordinates delegatingEvent,
      byte[] bytes,
      Set<EventSignature> signatures) {
    super(
        version,
        format,
        identifier,
        sequenceNumber,
        previous,
        signingThreshold,
        keys,
        nextKeys,
        witnessThreshold,
        delegatingEvent,
        bytes,
        signatures);

    requireNonNull(removedWitnesses);
    requireNonNull(addedWitnesses);
    requireNonNull(seals);

    this.removedWitnesses = List.copyOf(removedWitnesses);
    this.addedWitnesses = List.copyOf(addedWitnesses);
    this.seals = List.copyOf(seals);
  }

  @Override
  public List<BasicIdentifier> removedWitnesses() {
    return this.removedWitnesses;
  }

  @Override
  public List<BasicIdentifier> addedWitnesses() {
    return this.addedWitnesses;
  }

  @Override
  public List<Seal> seals() {
    return this.seals;
  }

}
