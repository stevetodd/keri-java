package foundation.identity.keri.api.event;

import java.util.Set;

public interface ReceiptFromTransferableIdentifierEvent extends ReceiptEvent {

  KeyEventCoordinates keyEstablishmentEvent();

  Set<AttachedEventSignature> signatures();

}
