package foundation.identity.keri.api.identifier;

import foundation.identity.keri.api.crypto.Signature;

import java.util.Objects;

public interface SelfSigningIdentifier extends Identifier {

  @Override
  default boolean transferable() {
    return true;
  }

  Signature signature();

  static boolean equals(SelfSigningIdentifier prefix, Object o) {
    if (prefix == o) {
      return true;
    }

    if (o == null) {
      return false;
    }

    if (!(o instanceof SelfSigningIdentifier)) {
      return false;
    }

    return Signature.equals(prefix.signature(), ((SelfSigningIdentifier) o).signature());
  }

  static int hashCode(SelfSigningIdentifier prefix) {
    return Objects.hash(prefix.signature());
  }

}
