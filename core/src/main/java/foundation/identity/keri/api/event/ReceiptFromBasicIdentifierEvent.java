package foundation.identity.keri.api.event;

import java.util.Set;

public interface ReceiptFromBasicIdentifierEvent extends ReceiptEvent {

  Set<EventSignature> receipts();

}
