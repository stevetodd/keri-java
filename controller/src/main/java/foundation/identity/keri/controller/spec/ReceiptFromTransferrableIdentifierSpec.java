package foundation.identity.keri.controller.spec;

import foundation.identity.keri.api.crypto.StandardFormats;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;

import static java.util.Objects.requireNonNull;

public class ReceiptFromTransferrableIdentifierSpec {

  private final Format format;
  private final EventSignature receipt;

  public ReceiptFromTransferrableIdentifierSpec(
      Format format,
      EventSignature receipt) {
    this.format = requireNonNull(format);
    this.receipt = requireNonNull(receipt);
  }

  public static Builder builder() {
    return new Builder();
  }

  public Format format() {
    return this.format;
  }

  public EventSignature receipt() {
    return this.receipt;
  }

  public static class Builder {
    private Format format = StandardFormats.JSON;

    private EventSignature receipt;

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

    public Builder receipt(EventSignature receipt) {
      this.receipt = requireNonNull(receipt);
      return this;
    }

    public ReceiptFromTransferrableIdentifierSpec build() {
      return new ReceiptFromTransferrableIdentifierSpec(
          this.format,
          this.receipt);
    }

  }

}
