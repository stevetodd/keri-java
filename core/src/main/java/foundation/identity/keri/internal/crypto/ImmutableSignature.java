package foundation.identity.keri.internal.crypto;

import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.crypto.SignatureAlgorithm;

import static foundation.identity.keri.QualifiedBase64.qb64;

public class ImmutableSignature implements Signature {

  final SignatureAlgorithm algorithm;
  final byte[] bytes;

  public ImmutableSignature(SignatureAlgorithm algorithm, byte[] bytes) {
    this.algorithm = algorithm;
    this.bytes = bytes.clone();
  }

  @Override
  public SignatureAlgorithm algorithm() {
    return this.algorithm;
  }

  @Override
  public byte[] bytes() {
    return this.bytes.clone();
  }

  @Override
  public int hashCode() {
    return Signature.hashCode(this);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof Signature)) {
      return false;
    }
    return Signature.equals(this, (Signature) obj);
  }

  @Override
  public String toString() {
    return qb64(this);
  }

}
