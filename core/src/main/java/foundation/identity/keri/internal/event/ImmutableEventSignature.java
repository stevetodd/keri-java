package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.EventSignatureCoordinates;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.KeyCoordinates;

import java.util.Objects;

public class ImmutableEventSignature implements EventSignature {

  private final EventSignatureCoordinates coordinates;
  private final KeyCoordinates keyCoordinates;
  private final Signature signature;

  public ImmutableEventSignature(EventSignatureCoordinates coordinates,
                                 KeyCoordinates keyCoordinates, Signature signature) {
    this.coordinates = coordinates;
    this.keyCoordinates = keyCoordinates;
    this.signature = signature;
  }

  public static ImmutableEventSignature of(IdentifierEventCoordinatesWithDigest eventCoordinates,
                                           KeyCoordinates keyCoordinates, Signature signature) {
    return new ImmutableEventSignature(
        ImmutableEventSignatureCoordinates.of(eventCoordinates, keyCoordinates),
        keyCoordinates,
        signature);
  }

  @Override
  public EventSignatureCoordinates event() {
    return this.coordinates;
  }

  @Override
  public KeyCoordinates key() {
    return this.keyCoordinates;
  }

  @Override
  public Signature signature() {
    return this.signature;
  }

  @Override
  public int hashCode() {
    return Objects.hash(coordinates, signature);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    ImmutableEventSignature other = (ImmutableEventSignature) obj;
    return Objects.equals(this.coordinates, other.coordinates)
        && Objects.equals(this.signature, other.signature);
  }

  @Override
  public String toString() {
    return "ImmutableEventSignature [coordinates=" + this.coordinates
        + ", signature=" + signature + "]";
  }

}
