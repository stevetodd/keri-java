package foundation.identity.keri.controller.spec;

import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.crypto.SignatureAlgorithm;
import foundation.identity.keri.api.crypto.StandardSignatureAlgorithms;
import foundation.identity.keri.crypto.SignatureOperations;

import java.security.PrivateKey;

import static java.util.Objects.requireNonNull;

public class PrivateKeySigner implements Signer {

  private final int keyIndex;
  private final PrivateKey privateKey;
  private final SignatureAlgorithm algorithm;
  private final SignatureOperations ops;

  public PrivateKeySigner(int keyIndex, PrivateKey privateKey) {
    this.keyIndex = keyIndex;
    this.privateKey = requireNonNull(privateKey);
    this.algorithm = StandardSignatureAlgorithms.lookup(privateKey);
    this.ops = SignatureOperations.lookup(this.algorithm);
  }

  @Override
  public int keyIndex() {
    return this.keyIndex;
  }

  @Override
  public SignatureAlgorithm algorithm() {
    return this.algorithm;
  }

  @Override
  public Signature sign(byte[] bytes) {
    return this.ops.sign(bytes, this.privateKey);
  }

}
