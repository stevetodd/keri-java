package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.KeyEventCoordinates;

import java.util.Map;
import java.util.Objects;

public class ImmutableEventSignature implements EventSignature {

  private final KeyEventCoordinates event;
  private final KeyEventCoordinates keyEstablishmentEvent;
  private final Map<Integer, Signature> signatures;

  public ImmutableEventSignature(
      KeyEventCoordinates event,
      KeyEventCoordinates keyEstablishmentEvent,
      Map<Integer, Signature> signatures) {
    this.event = event;
    this.keyEstablishmentEvent = keyEstablishmentEvent;
    this.signatures = Map.copyOf(signatures);
  }

  @Override
  public KeyEventCoordinates event() {
    return this.event;
  }

  @Override
  public KeyEventCoordinates keyEstablishmentEvent() {
    return this.keyEstablishmentEvent;
  }

  @Override
  public Map<Integer, Signature> signatures() {
    return this.signatures;
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
        && Objects.equals(this.keyEstablishmentEvent, that.keyEstablishmentEvent())
        && Objects.equals(this.signatures, that.signatures());
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.event, this.keyEstablishmentEvent, this.signatures);
  }

  @Override
  public String toString() {
    return "ImmutableEventSignature [" +
        "event=" + this.event + ", " +
        "keyEstablishmentEvent=" + this.keyEstablishmentEvent + ", " +
        "signatures=" + this.signatures +
        "]";
  }

}
