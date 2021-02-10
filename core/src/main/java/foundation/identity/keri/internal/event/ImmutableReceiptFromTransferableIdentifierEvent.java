package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.ReceiptFromTransferableIdentifierEvent;

import java.util.Set;

public class ImmutableReceiptFromTransferableIdentifierEvent extends AbstractImmutableEvent
    implements ReceiptFromTransferableIdentifierEvent {

  private final IdentifierEventCoordinatesWithDigest event;
  private final IdentifierEventCoordinatesWithDigest keyEstablishmentEvent;
  private final Set<AttachedEventSignature> signatures;

  public ImmutableReceiptFromTransferableIdentifierEvent(
      byte[] bytes,
      Version version,
      Format format,
      IdentifierEventCoordinatesWithDigest event,
      IdentifierEventCoordinatesWithDigest keyEstablishmentEvent,
      Set<AttachedEventSignature> signatures) {
    super(bytes, version, format);
    this.event = event;
    this.keyEstablishmentEvent = keyEstablishmentEvent;
    this.signatures = Set.copyOf(signatures);
  }

  @Override
  public IdentifierEventCoordinatesWithDigest event() {
    return this.event;
  }

  @Override
  public IdentifierEventCoordinatesWithDigest keyEstablishmentEvent() {
    return this.keyEstablishmentEvent;
  }

  @Override
  public Set<AttachedEventSignature> signatures() {
    return this.signatures;
  }

}
