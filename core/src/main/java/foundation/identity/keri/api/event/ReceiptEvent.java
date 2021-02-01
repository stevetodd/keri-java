package foundation.identity.keri.api.event;

import java.util.Set;

public interface ReceiptEvent extends Event {

  @Override
  default EventType type() {
    return EventType.RECEIPT;
  }

  Set<EventSignature> receipts();

}
