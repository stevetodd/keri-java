package foundation.identity.keri.internal.identifier;

import foundation.identity.keri.QualifiedBase64;
import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.identifier.SelfSigningIdentifier;

import java.util.Objects;

public class ImmutableSelfSigningIdentifier implements SelfSigningIdentifier {

  final Signature signature;

  public ImmutableSelfSigningIdentifier(Signature signature) {
    this.signature = signature;
  }

  @Override
  public Signature signature() {
    return this.signature;
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.signature);
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
    var other = (ImmutableSelfSigningIdentifier) obj;
    return Objects.equals(this.signature, other.signature);
  }

  @Override
  public String toString() {
    return QualifiedBase64.qb64(this);
  }

}
