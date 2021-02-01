package foundation.identity.keri.api.event;

public interface ReceiptFromTransferrableIdentifierEvent extends Event {

  @Override
  default EventType type() {
    return EventType.RECEIPT_FROM_TRANSFERRABLE;
  }

  EventSignature receipt();

}
