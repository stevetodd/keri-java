package foundation.identity.keri.api.event;

import java.util.Set;

public interface ReceiptFromTransferableIdentifierEvent extends Event {

  @Override
  default EventType type() {
    return EventType.RECEIPT_FROM_TRANSFERRABLE;
  }

  IdentifierEventCoordinatesWithDigest event();

  IdentifierEventCoordinatesWithDigest keyEstablishmentEvent();

  Set<AttachedEventSignature> signatures();

}
