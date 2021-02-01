package foundation.identity.keri.api.seal;

import foundation.identity.keri.api.crypto.Digest;

public interface DigestSeal extends Seal {

  Digest digest();

}
