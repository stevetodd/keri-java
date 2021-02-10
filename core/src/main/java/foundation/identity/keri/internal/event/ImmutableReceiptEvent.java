package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.ReceiptEvent;
import foundation.identity.keri.api.identifier.BasicIdentifier;

import java.util.Set;

import static java.util.Objects.requireNonNull;

public class ImmutableReceiptEvent extends AbstractImmutableEvent
    implements ReceiptEvent {

  private final Set<EventSignature> receipts;

  public ImmutableReceiptEvent(
      byte[] bytes,
      Version version,
      Format format,
      Set<EventSignature> receipts) {
    super(bytes, version, format);
    this.receipts = Set.copyOf(requireNonNull(receipts));

    var first = this.receipts.stream().findFirst();
    if (first.isPresent()) {
      var event = first.get().event();
      this.receipts.forEach(r -> {
        if (!r.event().equals(event)) {
          throw new IllegalArgumentException("receipts are not all for the same event");
        }
        if (!(r.key().establishmentEvent().identifier() instanceof BasicIdentifier)) {
          throw new IllegalArgumentException("only BasicIdentifiers permitted as signers");
        }
      });
    }
  }

  @Override
  public Set<EventSignature> receipts() {
    return this.receipts;
  }

}
