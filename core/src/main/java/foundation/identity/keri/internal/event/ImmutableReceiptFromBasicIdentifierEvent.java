package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.ReceiptFromBasicIdentifierEvent;
import foundation.identity.keri.api.identifier.BasicIdentifier;

import java.util.Set;

import static java.util.Objects.requireNonNull;

public class ImmutableReceiptFromBasicIdentifierEvent extends AbstractImmutableEvent
    implements ReceiptFromBasicIdentifierEvent {

  private final KeyEventCoordinates event;
  private final Set<EventSignature> receipts;

  public ImmutableReceiptFromBasicIdentifierEvent(
      byte[] bytes,
      Version version,
      Format format,
      Set<EventSignature> receipts) {
    super(bytes, version, format);
    this.receipts = Set.copyOf(requireNonNull(receipts, "receipts"));

    var first = this.receipts.stream().findFirst();
    if (first.isPresent()) {
      this.event = first.get().event();
      this.receipts.forEach(r -> {
        if (!r.event().equals(this.event)) {
          throw new IllegalArgumentException("receipts are not all for the same event");
        }
        if (!(r.key().establishmentEvent().identifier() instanceof BasicIdentifier)) {
          throw new IllegalArgumentException("only BasicIdentifiers permitted as signers");
        }
      });
    } else {
      throw new IllegalArgumentException("at least one receipt is required");
    }
  }

  @Override
  public KeyEventCoordinates event() {
    return this.event;
  }

  @Override
  public Set<EventSignature> receipts() {
    return this.receipts;
  }

}
