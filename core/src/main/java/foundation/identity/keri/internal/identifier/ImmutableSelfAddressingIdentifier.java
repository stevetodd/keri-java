package foundation.identity.keri.internal.identifier;

import foundation.identity.keri.QualifiedBase64;
import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;

import java.util.Objects;

public class ImmutableSelfAddressingIdentifier implements SelfAddressingIdentifier {

  final Digest digest;

  public ImmutableSelfAddressingIdentifier(Digest digest) {
    this.digest = digest;
  }

  @Override
  public Digest digest() {
    return this.digest;
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.digest);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    var other = (ImmutableSelfAddressingIdentifier) obj;
    return Objects.equals(this.digest, other.digest);
  }

  @Override
  public String toString() {
    return QualifiedBase64.qb64(this);
  }

}
