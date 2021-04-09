package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.KeyEventCoordinates;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

public class ImmutableAttachedEventSignature implements AttachedEventSignature {

  private final KeyEventCoordinates event;
  private final int keyIndex;
  private final Signature signature;

  public ImmutableAttachedEventSignature(KeyEventCoordinates event, int keyIndex, Signature signature) {
    if (keyIndex < 0) {
      throw new IllegalArgumentException("keyIndex must be >= 0");
    }

    this.event = requireNonNull(event, "event");
    this.keyIndex = keyIndex;
    this.signature = requireNonNull(signature, "signature");
  }

  public static ImmutableAttachedEventSignature convert(EventSignature eventSignature) {
    return new ImmutableAttachedEventSignature(
        eventSignature.event(),
        eventSignature.key().keyIndex(),
        eventSignature.signature());
  }

  @Override
  public KeyEventCoordinates event() {
    return this.event;
  }

  @Override
  public int keyIndex() {
    return this.keyIndex;
  }

  @Override
  public Signature signature() {
    return this.signature;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (!(o instanceof AttachedEventSignature)) {
      return false;
    }

    var that = (AttachedEventSignature) o;
    return this.keyIndex == that.keyIndex()
           && Objects.equals(this.event, that.event())
           && Objects.equals(this.signature, that.signature());
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.event, this.keyIndex, this.signature);
  }

  @Override
  public String toString() {
    return this.event + ":" + this.keyIndex + "→" + this.signature;
  }
}
