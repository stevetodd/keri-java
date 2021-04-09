package foundation.identity.keri.controller.spec;

import foundation.identity.keri.api.crypto.StandardFormats;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.internal.event.ImmutableKeyEventCoordinates;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;

public class ReceiptSpec {

  private final KeyEventCoordinates event;
  private final Format format;
  private final Set<EventSignature> receipts;

  public ReceiptSpec(
      Format format,
      KeyEventCoordinates event,
      Set<EventSignature> receipts) {
    this.format = format;
    this.event = event;
    this.receipts = Set.copyOf(requireNonNull(receipts));
  }

  public static Builder builder(KeyEvent event) {
    return builder(ImmutableKeyEventCoordinates.of(event));
  }

  public static Builder builder(KeyEventCoordinates event) {
    return new Builder(event);
  }

  public KeyEventCoordinates event() {
    return this.event;
  }

  public Format format() {
    return this.format;
  }

  public Set<EventSignature> receipts() {
    return this.receipts;
  }

  public static class Builder {
    private final KeyEventCoordinates event;
    private final Set<EventSignature> receipts = new HashSet<>();
    private Format format = StandardFormats.JSON;

    public Builder(KeyEventCoordinates event) {
      this.event = event;
    }

    public Builder json() {
      this.format = StandardFormats.JSON;
      return this;
    }

    public Builder cbor() {
      this.format = StandardFormats.CBOR;
      return this;
    }

    public Builder messagePack() {
      this.format = StandardFormats.MESSAGE_PACK;
      return this;
    }

    public Builder receipts(EventSignature... receipts) {
      this.receipts.addAll(Arrays.asList(receipts));
      return this;
    }

    public Builder receipts(Collection<EventSignature> receipts) {
      this.receipts.addAll(receipts);
      return this;
    }

    public ReceiptSpec build() {
      return new ReceiptSpec(
          this.format,
          this.event,
          this.receipts);
    }

  }

}
