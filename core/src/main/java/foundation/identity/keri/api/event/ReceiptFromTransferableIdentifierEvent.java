package foundation.identity.keri.api.event;

import java.util.Set;

public interface ReceiptFromTransferableIdentifierEvent extends ReceiptEvent {

  @Override
  default EventType type() {
    return EventType.RECEIPT_FROM_TRANSFERABLE;
  }

  KeyEventCoordinates keyEstablishmentEvent();

  Set<AttachedEventSignature> signatures();

}
