package foundation.identity.keri.internal.seal;

import foundation.identity.keri.api.seal.DigestSeal;
import foundation.identity.keri.crypto.Digest;

public class ImmutableDigestSeal implements DigestSeal {

  private final Digest digest;

  public ImmutableDigestSeal(Digest digest) {
    this.digest = digest;
  }

  @Override
  public Digest digest() {
    return this.digest;
  }

}
