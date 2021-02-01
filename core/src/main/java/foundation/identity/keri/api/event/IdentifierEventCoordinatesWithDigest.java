package foundation.identity.keri.api.event;

import foundation.identity.keri.api.crypto.Digest;

public interface IdentifierEventCoordinatesWithDigest extends IdentifierEventCoordinates {

  IdentifierEventCoordinatesWithDigest NONE = new None();

  Digest digest();

  class None extends IdentifierEventCoordinates.None implements IdentifierEventCoordinatesWithDigest {

    None() {
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
