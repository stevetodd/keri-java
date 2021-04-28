package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.Signature;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

public abstract class AbstractImmutableEstablishmentEvent extends AbstractImmutableKeyEvent
    implements EstablishmentEvent {

  final SigningThreshold signingThreshold;

  final List<PublicKey> keys;

  final KeyConfigurationDigest nextKeys;

  final int witnessThreshold;

  public AbstractImmutableEstablishmentEvent(
      Version version,
      Format format,
      Identifier identifier,
      long sequenceNumber,
      KeyEventCoordinates previous,
      SigningThreshold signingThreshold,
      List<PublicKey> keys,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
      byte[] bytes,
      Map<Integer, Signature> signatures,
      Map<Integer, Signature> receipts,
      Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts) {
    super(version, format, identifier, sequenceNumber, previous, bytes, signatures, receipts, otherReceipts);

    this.signingThreshold = signingThreshold;
    this.keys = List.copyOf(requireNonNull(keys, "keys"));
    this.nextKeys = nextKeys;
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
    return Optional.ofNullable(this.nextKeys);
  }

  @Override
  public int witnessThreshold() {
    return this.witnessThreshold;
  }

}
