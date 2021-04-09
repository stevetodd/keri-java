package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.ReceiptFromTransferableIdentifierEvent;

import java.util.Set;

public class ImmutableReceiptFromTransferableIdentifierEvent extends AbstractImmutableEvent
    implements ReceiptFromTransferableIdentifierEvent {

  private final KeyEventCoordinates event;
  private final KeyEventCoordinates keyEstablishmentEvent;
  private final Set<AttachedEventSignature> signatures;

  public ImmutableReceiptFromTransferableIdentifierEvent(
      byte[] bytes,
      Version version,
      Format format,
      KeyEventCoordinates event,
      KeyEventCoordinates keyEstablishmentEvent,
      Set<AttachedEventSignature> signatures) {
    super(bytes, version, format);
    this.event = event;
    this.keyEstablishmentEvent = keyEstablishmentEvent;
    this.signatures = Set.copyOf(signatures);
  }

  @Override
  public KeyEventCoordinates event() {
    return this.event;
  }

  @Override
  public KeyEventCoordinates keyEstablishmentEvent() {
    return this.keyEstablishmentEvent;
  }

  @Override
  public Set<AttachedEventSignature> signatures() {
    return this.signatures;
  }

}
