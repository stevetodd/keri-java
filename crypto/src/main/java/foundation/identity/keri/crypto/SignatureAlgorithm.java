package foundation.identity.keri.crypto;

import java.util.Objects;

public interface SignatureAlgorithm {

  static boolean equals(SignatureAlgorithm algorithm, Object o) {
    if (algorithm == o) {
      return true;
    }

    if (o == null) {
      return false;
    }

    if (!(o instanceof SignatureAlgorithm)) {
      return false;
    }

    var otherAlgorithm = (SignatureAlgorithm) o;
    return algorithm.algorithmName().equals(otherAlgorithm.algorithmName())
        && algorithm.parameters().equals(otherAlgorithm.parameters());
  }

  static int hashCode(SignatureAlgorithm algorithm) {
    return Objects.hash(
        algorithm.algorithmName(),
        algorithm.parameters());
  }

  String algorithmName();

  SignatureAlgorithmParameters parameters();

  int publicKeyLength();

  int privateKeyLength();

  int signatureLength();

}
