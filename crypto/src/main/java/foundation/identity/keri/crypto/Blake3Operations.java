package foundation.identity.keri.crypto;

import io.github.rctcwyvrn.blake3.Blake3;

public class Blake3Operations implements DigestOperations {

  final int length;
  final DigestAlgorithm algorithm;

  public Blake3Operations(int length) {
    this.length = length;
    this.algorithm = switch (length) {
      case 32 -> StandardDigestAlgorithms.BLAKE3_256;
      case 64 -> StandardDigestAlgorithms.BLAKE3_512;
      default -> throw new RuntimeException("Invalid digest length");
    };
  }

  @Override
  public Digest digest(byte[] bytes) {
    var digester = Blake3.newInstance();
    digester.update(bytes);
    return new ImmutableDigest(this.algorithm, digester.digest(this.length));
  }

}
