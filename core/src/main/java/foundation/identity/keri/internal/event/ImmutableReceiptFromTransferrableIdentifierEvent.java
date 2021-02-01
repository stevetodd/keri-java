package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.ReceiptFromTransferrableIdentifierEvent;

import static java.util.Objects.requireNonNull;

public class ImmutableReceiptFromTransferrableIdentifierEvent extends AbstractImmutableEvent
    implements ReceiptFromTransferrableIdentifierEvent {

  private final EventSignature receipt;

  public ImmutableReceiptFromTransferrableIdentifierEvent(
      byte[] bytes,
      Version version,
      Format format,
      EventSignature receipt) {
    super(bytes, version, format);
    this.receipt = requireNonNull(receipt);
  }

  @Override
  public EventSignature receipt() {
    return this.receipt;
  }

}
