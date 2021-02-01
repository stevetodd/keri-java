package foundation.identity.keri.api.identifier;

import java.security.PublicKey;
import java.util.Objects;

public interface BasicIdentifier extends Identifier {

  static boolean equals(BasicIdentifier prefix, Object o) {
    if (prefix == o) {
      return true;
    }

    if (o == null) {
      return false;
    }

    if (!(o instanceof BasicIdentifier)) {
      return false;
    }

    return prefix.publicKey().equals(((BasicIdentifier) o).publicKey());
  }

  static int hashCode(BasicIdentifier prefix) {
    return Objects.hash(prefix.publicKey());
  }

  @Override
  default boolean transferable() {
    return false;
  }

  PublicKey publicKey();

}
