package foundation.identity.keri.crypto;

import java.util.Arrays;
import java.util.Objects;

public interface Digest {

  DigestAlgorithm algorithm();

  byte[] bytes();

  Digest NONE = new None();

  static boolean equals(Digest d1, Digest d2) {
    if (d1 == d2) {
      return true;
    }

    if (d2 == null) {
      return false;
    }

    return d1.algorithm().equals(d2.algorithm())
        && Arrays.equals(d1.bytes(), d2.bytes());
  }

  static int hashCode(Digest digest) {
    return Objects.hash(
        digest.algorithm(),
        Arrays.hashCode(digest.bytes()));
  }

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
      if (!(obj instanceof Digest)) {
        return false;
      }
      return Digest.equals(this, (Digest) obj);
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
