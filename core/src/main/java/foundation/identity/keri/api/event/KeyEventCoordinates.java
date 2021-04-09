package foundation.identity.keri.api.event;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;

public interface KeyEventCoordinates {

  KeyEventCoordinates NONE = new None();

  Identifier identifier();

  BigInteger sequenceNumber();

  Digest digest();

  class None implements KeyEventCoordinates {

    None() {
    }

    @Override
    public Identifier identifier() {
      return Identifier.NONE;
    }

    @Override
    public BigInteger sequenceNumber() {
      return BigInteger.valueOf(-1);
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
