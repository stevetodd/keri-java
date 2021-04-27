package foundation.identity.keri.controller.spec;

import foundation.identity.keri.crypto.Signature;
import foundation.identity.keri.crypto.SignatureAlgorithm;

public interface Signer {

  int keyIndex();

  SignatureAlgorithm algorithm();

  Signature sign(byte[] bytes);

}
