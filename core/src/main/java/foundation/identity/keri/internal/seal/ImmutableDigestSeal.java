package foundation.identity.keri.internal.seal;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.seal.DigestSeal;

public class ImmutableDigestSeal implements DigestSeal {

  private final Digest digest;

  public ImmutableDigestSeal(Digest digest) {
    this.digest = digest;
  }

  public Digest digest() {
    return this.digest;
  }

}
