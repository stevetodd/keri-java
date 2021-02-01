package foundation.identity.keri.api.crypto;

import java.util.Arrays;
import java.util.Objects;

public interface Signature {

  static boolean equals(Signature signature, Object o) {
    if (signature == o) {
      return true;
    }

    if (o == null) {
      return false;
    }

    if (!(o instanceof Signature)) {
      return false;
    }

    var otherSignature = (Signature) o;
    return signature.algorithm().equals(otherSignature.algorithm())
        && Arrays.equals(signature.bytes(), otherSignature.bytes());
  }

  static int hashCode(Signature signature) {
    return Objects.hash(
        signature.algorithm(),
        Arrays.hashCode(signature.bytes()));
  }

  SignatureAlgorithm algorithm();

  byte[] bytes();

}
