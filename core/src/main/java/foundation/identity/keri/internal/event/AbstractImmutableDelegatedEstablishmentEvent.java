package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.event.DelegatedEstablishmentEvent;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.Identifier;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public abstract class AbstractImmutableDelegatedEstablishmentEvent extends AbstractImmutableEstablishmentEvent
    implements DelegatedEstablishmentEvent {

  private final DelegatingEventCoordinates delegatingEvent;

  public AbstractImmutableDelegatedEstablishmentEvent(
      Version version,
      Format format,
      Identifier identifier,
      long sequenceNumber,
      KeyEventCoordinates previous,
      SigningThreshold signingThreshold,
      List<PublicKey> keys,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
      DelegatingEventCoordinates delegatingEvent,
      byte[] bytes,
      Map<Integer, Signature> signatures,
      Map<Integer, Signature> receipts,
      Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts) {
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
        signatures,
        receipts,
        otherReceipts);
    this.delegatingEvent = requireNonNull(delegatingEvent, "delegatingEvent");
  }

  @Override
  public DelegatingEventCoordinates delegatingEvent() {
    return this.delegatingEvent;
  }

}
