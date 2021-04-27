package foundation.identity.keri.crypto;

import java.util.Objects;

public interface EcDSAParameters extends SignatureAlgorithmParameters {

  static boolean equals(EcDSAParameters parameters, Object o) {
    if (parameters == o) {
      return true;
    }

    if (o == null) {
      return false;
    }

    if (!(o instanceof EcDSAParameters)) {
      return false;
    }

    var otherAlgorithm = (EcDSAParameters) o;
    return parameters.digestAlgorithm().equals(otherAlgorithm.digestAlgorithm())
        && parameters.curveName().equals(otherAlgorithm.curveName());
  }

  static int hashCode(EcDSAParameters algorithm) {
    return Objects.hash(
        algorithm.digestAlgorithm(),
        algorithm.curveName());
  }

  String digestAlgorithm();

  String curveName();

}
