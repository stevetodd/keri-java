package foundation.identity.keri.internal.crypto;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;

import static foundation.identity.keri.QualifiedBase64.qb64;
import static java.util.Objects.requireNonNull;

public class ImmutableDigest implements Digest {

  final DigestAlgorithm algorithm;
  final byte[] bytes;

  public ImmutableDigest(DigestAlgorithm algorithm, byte[] bytes) {
    requireNonNull(algorithm);
    requireNonNull(bytes);

    this.algorithm = algorithm;
    this.bytes = bytes.clone();
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
    return Digest.equals(this, obj);
  }

  @Override
  public String toString() {
    return qb64(this);
  }

}
