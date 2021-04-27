package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.Digest;

public interface KeyEventCoordinates {

  KeyEventCoordinates NONE = new None();

  Identifier identifier();

  long sequenceNumber();

  Digest digest();

  class None implements KeyEventCoordinates {

    None() {
    }

    @Override
    public Identifier identifier() {
      return Identifier.NONE;
    }

    @Override
    public long sequenceNumber() {
      return -1;
    }

    @Override
    public Digest digest() {
      return Digest.NONE;
    }

    @Override
    public String toString() {
      return "NONE";
    }

  }

}
