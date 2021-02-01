package foundation.identity.keri.controller.spec;

import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.crypto.SignatureAlgorithm;

public interface Signer {

  SignatureAlgorithm algorithm();

  Signature sign(byte[] bytes);

}
