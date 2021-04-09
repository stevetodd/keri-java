package foundation.identity.keri.controller.spec;

import foundation.identity.keri.api.crypto.StandardFormats;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEventCoordinates;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;

public class ReceiptFromTransferableIdentifierSpec {

  private final Format format;
  private final KeyEventCoordinates event;
  private final Set<EventSignature> signatures;

  public ReceiptFromTransferableIdentifierSpec(
      Format format,
      KeyEventCoordinates event,
      Set<EventSignature> signatures) {
    this.format = requireNonNull(format);
    this.event = requireNonNull(event);
    this.signatures = Set.copyOf(signatures);
  }

  public static Builder builder() {
    return new Builder();
  }

  public Format format() {
    return this.format;
  }

  public KeyEventCoordinates event() {
    return this.event;
  }

  public Set<EventSignature> signatures() {
    return this.signatures;
  }

  public static class Builder {
    private Format format = StandardFormats.JSON;

    private final Set<EventSignature> signatures = new HashSet<>();

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

    public Builder signature(EventSignature signature) {
      this.signatures.add(requireNonNull(signature));
      return this;
    }

    public Builder signatures(Collection<EventSignature> signatures) {
      this.signatures.addAll(signatures);
      return this;
    }

    public ReceiptFromTransferableIdentifierSpec build() {
      var event = this.signatures.stream()
          .findFirst()
          .get()
          .event();

      for (var es : this.signatures) {
        if (!es.event().equals(event)) {
          throw new IllegalArgumentException("all signatures must be for the same event");
        }
      }

      return new ReceiptFromTransferableIdentifierSpec(
          this.format,
          event,
          this.signatures);
    }

  }

}
