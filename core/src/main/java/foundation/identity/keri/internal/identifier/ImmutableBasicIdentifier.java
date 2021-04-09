package foundation.identity.keri.internal.identifier;

import foundation.identity.keri.api.identifier.BasicIdentifier;

import java.security.PublicKey;

public class ImmutableBasicIdentifier implements BasicIdentifier {

  final PublicKey publicKey;

  public ImmutableBasicIdentifier(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  @Override
  public PublicKey publicKey() {
    return this.publicKey;
  }

  @Override
  public int hashCode() {
    return BasicIdentifier.hashCode(this);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof BasicIdentifier)) {
      return false;
    }
    return BasicIdentifier.equals(this, (BasicIdentifier) obj);
  }

  @Override
  public String toString() {
    return "ImmutableBasicPrefix [publicKey=" + this.publicKey + "]";
  }

}
