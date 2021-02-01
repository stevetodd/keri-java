package foundation.identity.keri.crypto;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.internal.crypto.ImmutableDigest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class JcaDigestOperations implements DigestOperations {

  private final DigestAlgorithm digestAlgorithm;

  public JcaDigestOperations(DigestAlgorithm digestAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
  }

  @Override
  public Digest digest(byte[] bytes) {
    try {
      var digester = MessageDigest.getInstance(this.digestAlgorithm.algorithmName());

      return new ImmutableDigest(this.digestAlgorithm, digester.digest(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

}
