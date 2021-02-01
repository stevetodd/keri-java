package foundation.identity.keri.internal.seal;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.seal.MerkleTreeRootSeal;

public class ImmutableMerkleTreeRootSeal implements MerkleTreeRootSeal {

  private final Digest digest;

  public ImmutableMerkleTreeRootSeal(Digest digest) {
    this.digest = digest;
  }

  public Digest digest() {
    return this.digest;
  }

}
