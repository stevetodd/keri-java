package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.DelegatedRotationEvent;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.SigningThreshold;
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
      long sequenceNumber,
      KeyEventCoordinates previous,
      SigningThreshold signingThreshold,
      List<PublicKey> keys,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
      List<BasicIdentifier> removedWitnesses,
      List<BasicIdentifier> addedWitnesses,
      List<Seal> seals,
      DelegatingEventCoordinates delegatingEvent,
      byte[] bytes,
      Set<AttachedEventSignature> signatures) {
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
    this.removedWitnesses = List.copyOf(requireNonNull(removedWitnesses, "removedWitnesses"));
    this.addedWitnesses = List.copyOf(requireNonNull(addedWitnesses, "addedWitnesses"));
    this.seals = List.copyOf(requireNonNull(seals, "seals"));
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
