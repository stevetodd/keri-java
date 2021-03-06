package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.crypto.Digest;
import foundation.identity.keri.crypto.ImmutableDigest;

public class ImmutableKeyConfigurationDigest extends ImmutableDigest implements KeyConfigurationDigest {

  public ImmutableKeyConfigurationDigest(Digest digest) {
    super(digest.algorithm(), digest.bytes());
  }

}
