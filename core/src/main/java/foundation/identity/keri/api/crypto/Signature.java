package foundation.identity.keri.api.crypto;

import java.util.Arrays;
import java.util.Objects;

public interface Signature {

  SignatureAlgorithm algorithm();

  byte[] bytes();

  static boolean equals(Signature s1, Signature s2) {
    if (s1 == s2) {
      return true;
    }

    if (s2 == null) {
      return false;
    }

    return s1.algorithm().equals(s2.algorithm())
        && Arrays.equals(s1.bytes(), s2.bytes());
  }

  static int hashCode(Signature signature) {
    return Objects.hash(
        signature.algorithm(),
        Arrays.hashCode(signature.bytes()));
  }

}
