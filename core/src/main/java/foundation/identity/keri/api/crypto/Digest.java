package foundation.identity.keri.api.crypto;

import java.util.Arrays;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

public interface Digest {

  Digest NONE = new None();

  static boolean equals(Digest digest, Object obj) {
    requireNonNull(digest);

    if (digest == obj) {
      return true;
    }

    if (obj == null) {
      return false;
    }

    if (!(obj instanceof Digest)) {
      return false;
    }

    var other = (Digest) obj;
    return digest.algorithm().equals(other.algorithm())
        && Arrays.equals(digest.bytes(), other.bytes());
  }

  static int hashCode(Digest digest) {
    return Objects.hash(
        digest.algorithm(),
        Arrays.hashCode(digest.bytes()));
  }

  DigestAlgorithm algorithm();

  byte[] bytes();

  class None implements Digest {

    @Override
    public byte[] bytes() {
      return new byte[0];
    }

    @Override
    public DigestAlgorithm algorithm() {
      return DigestAlgorithm.NONE;
    }

    @Override
    public boolean equals(Object obj) {
      return Digest.equals(this, obj);
    }

    @Override
    public int hashCode() {
      return Digest.hashCode(this);
    }

    @Override
    public String toString() {
      return "NONE";
    }

  }

}
