package foundation.identity.keri.api.seal;

import foundation.identity.keri.crypto.Digest;

public interface MerkleTreeRootSeal extends Seal {

  Digest digest();

}
