package foundation.identity.keri.api.event;

import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;

/**
 * Identifies the parameters required to identify a single event.
 *
 * @author stephen
 */
public interface IdentifierEventCoordinates {

  IdentifierEventCoordinates NONE = new None();

  Identifier identifier();

  BigInteger sequenceNumber();

  // do not extend--will be sealed in future versions
  class None implements IdentifierEventCoordinates {

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
    public String toString() {
      return "NONE";
    }

  }

}
