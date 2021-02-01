package foundation.identity.keri.api.crypto;

public interface DigestAlgorithm {

  DigestAlgorithm NONE = new None();

  String algorithmName();

  int digestLength();

  class None implements DigestAlgorithm {

    @Override
    public int digestLength() {
      return 0;
    }

    @Override
    public String algorithmName() {
      return "NONE";
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }

      if (obj == null) {
        return false;
      }

      if (!(obj instanceof DigestAlgorithm)) {
        return false;
      }

      var other = (DigestAlgorithm) obj;
      return this.algorithmName().equals(other.algorithmName())
          && this.digestLength() == other.digestLength();
    }

    @Override
    public int hashCode() {
      return 1;
    }

  }
}
