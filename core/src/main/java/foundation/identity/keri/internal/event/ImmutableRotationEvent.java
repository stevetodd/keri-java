package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

public final class ImmutableRotationEvent extends AbstractImmutableEstablishmentEvent implements RotationEvent {

  private final List<BasicIdentifier> removedWitnesses;

  private final List<BasicIdentifier> addedWitnesses;

  private final List<Seal> seals;

  public ImmutableRotationEvent(
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
        bytes,
        signatures);
    this.removedWitnesses = List.copyOf(requireNonNull(removedWitnesses));
    this.addedWitnesses = List.copyOf(requireNonNull(addedWitnesses));
    this.seals = List.copyOf(requireNonNull(seals));
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
