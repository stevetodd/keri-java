package foundation.identity.keri.api.event;

import foundation.identity.keri.crypto.Digest;
import foundation.identity.keri.crypto.DigestAlgorithm;

public interface KeyConfigurationDigest extends Digest {

  KeyConfigurationDigest NONE = new None();

  class None implements KeyConfigurationDigest {

    None() {
    }

    @Override
    public byte[] bytes() {
      return new byte[0];
    }

    @Override
    public DigestAlgorithm algorithm() {
      return DigestAlgorithm.NONE;
    }
  }

}
