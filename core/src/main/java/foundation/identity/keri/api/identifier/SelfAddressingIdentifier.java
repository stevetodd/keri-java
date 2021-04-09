package foundation.identity.keri.api.identifier;

import foundation.identity.keri.api.crypto.Digest;

import java.util.Objects;

public interface SelfAddressingIdentifier extends Identifier {

  @Override
  default boolean transferable() {
    return true;
  }

  Digest digest();

  static boolean equals(SelfAddressingIdentifier prefix, Object o) {
    if (prefix == o) {
      return true;
    }

    if (o == null) {
      return false;
    }

    if (!(o instanceof SelfAddressingIdentifier)) {
      return false;
    }

    return Digest.equals(prefix.digest(), ((SelfAddressingIdentifier) o).digest());
  }

  static int hashCode(SelfAddressingIdentifier prefix) {
    return Objects.hash(prefix.digest());
  }

}
