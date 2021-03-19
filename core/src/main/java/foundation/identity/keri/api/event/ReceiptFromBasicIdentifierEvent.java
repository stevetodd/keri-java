package foundation.identity.keri.api.event;

import java.util.Set;

public interface ReceiptFromBasicIdentifierEvent extends ReceiptEvent {

  @Override
  default EventType type() {
    return EventType.RECEIPT;
  }

  Set<EventSignature> receipts();

}
