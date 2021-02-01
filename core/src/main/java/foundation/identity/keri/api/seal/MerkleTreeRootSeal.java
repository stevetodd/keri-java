package foundation.identity.keri.api.seal;

import foundation.identity.keri.api.crypto.Digest;

public interface MerkleTreeRootSeal extends Seal {

  Digest digest();

}
