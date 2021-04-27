package foundation.identity.keri.crypto;

import static java.util.Objects.requireNonNull;

public class ImmutableDigest implements Digest {

  final DigestAlgorithm algorithm;
  final byte[] bytes;

  public ImmutableDigest(DigestAlgorithm algorithm, byte[] bytes) {
    this.algorithm = requireNonNull(algorithm);
    this.bytes = requireNonNull(bytes).clone();
  }

  @Override
  public DigestAlgorithm algorithm() {
    return this.algorithm;
  }

  @Override
  public byte[] bytes() {
    return this.bytes.clone();
  }

  @Override
  public int hashCode() {
    return Digest.hashCode(this);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof Digest)) {
      return false;
    }
    return Digest.equals(this, (Digest) obj);
  }

}
