package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.KeyCoordinates;

import java.util.Objects;

public class ImmutableEventSignature implements EventSignature {

  private final KeyEventCoordinates event;
  private final KeyCoordinates key;
  private final Signature signature;

  public ImmutableEventSignature(
      KeyEventCoordinates event,
      KeyCoordinates key,
      Signature signature) {
    this.event = event;
    this.key = key;
    this.signature = signature;
  }

  public static ImmutableEventSignature from(AttachedEventSignature attachedSignature, KeyEventCoordinates establishmentEvent) {
    var key = new ImmutableKeyCoordinates(establishmentEvent, attachedSignature.keyIndex());
    return new ImmutableEventSignature(attachedSignature.event(), key, attachedSignature.signature());
  }

  public static ImmutableEventSignature of(KeyEventCoordinates event,
                                           KeyCoordinates key, Signature signature) {
    return new ImmutableEventSignature(
        ImmutableEventSignatureCoordinates.of(event, key),
        key,
        signature);
  }

  @Override
  public KeyEventCoordinates event() {
    return this.event;
  }

  @Override
  public KeyCoordinates key() {
    return this.key;
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
    if (!(o instanceof EventSignature)) {
      return false;
    }
    var that = (EventSignature) o;
    return Objects.equals(this.event, that.event())
        && Objects.equals(this.key, that.key())
        && Objects.equals(this.signature, that.signature());
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.event, this.key, this.signature);
  }

  @Override
  public String toString() {
    return "ImmutableEventSignature [" +
        "event=" + this.event + ", " +
        "key=" + this.key + ", " +
        "signature=" + this.signature +
        "]";
  }

}
