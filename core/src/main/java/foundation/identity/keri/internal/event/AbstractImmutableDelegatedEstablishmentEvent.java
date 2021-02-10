package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.DelegatedEstablishmentEvent;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public abstract class AbstractImmutableDelegatedEstablishmentEvent extends AbstractImmutableEstablishmentEvent
    implements DelegatedEstablishmentEvent {

  private final DelegatingEventCoordinates delegatingEvent;

  public AbstractImmutableDelegatedEstablishmentEvent(
      Version version,
      Format format,
      Identifier identifier,
      BigInteger sequenceNumber,
      IdentifierEventCoordinatesWithDigest previous,
      int signingThreshold,
      List<PublicKey> keys,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
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
        bytes,
        signatures);
    this.delegatingEvent = Objects.requireNonNull(delegatingEvent, "delegatingEvent");
  }

  @Override
  public DelegatingEventCoordinates delegatingEvent() {
    return this.delegatingEvent;
  }

}
