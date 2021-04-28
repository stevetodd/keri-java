package foundation.identity.keri.internal.seal;

import foundation.identity.keri.api.seal.MerkleTreeRootSeal;
import foundation.identity.keri.crypto.Digest;

public class ImmutableMerkleTreeRootSeal implements MerkleTreeRootSeal {

  private final Digest digest;

  public ImmutableMerkleTreeRootSeal(Digest digest) {
    this.digest = digest;
  }

  @Override
  public Digest digest() {
    return this.digest;
  }

}
