package foundation.identity.keri.api.identifier;

import java.security.PublicKey;
import java.util.Objects;

public interface BasicIdentifier extends Identifier {

  static boolean equals(BasicIdentifier i1, BasicIdentifier i2) {
    if (i1 == i2) {
      return true;
    }

    if (i2 == null) {
      return false;
    }

    return i1.publicKey().equals(i2.publicKey());
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
