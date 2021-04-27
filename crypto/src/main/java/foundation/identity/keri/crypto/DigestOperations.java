package foundation.identity.keri.crypto;

import java.util.Arrays;

public interface DigestOperations {

  DigestOperations BLAKE2B_256 = new JcaDigestOperations(StandardDigestAlgorithms.BLAKE2B_256);
  DigestOperations BLAKE2B_512 = new JcaDigestOperations(StandardDigestAlgorithms.BLAKE2B_512);
  DigestOperations BLAKE2S_256 = new JcaDigestOperations(StandardDigestAlgorithms.BLAKE2S_256);
  DigestOperations BLAKE3_256 = new Blake3Operations(32);
  DigestOperations BLAKE3_512 = new Blake3Operations(64);
  DigestOperations SHA2_256 = new JcaDigestOperations(StandardDigestAlgorithms.SHA2_256);
  DigestOperations SHA2_512 = new JcaDigestOperations(StandardDigestAlgorithms.SHA2_512);
  DigestOperations SHA3_256 = new JcaDigestOperations(StandardDigestAlgorithms.BLAKE2B_256);
  DigestOperations SHA3_512 = new JcaDigestOperations(StandardDigestAlgorithms.BLAKE2B_256);

  DigestOperations DEFAULT = lookup(StandardDigestAlgorithms.DEFAULT);

  static DigestOperations lookup(DigestAlgorithm algorithm) {
    var stdAlgo = StandardDigestAlgorithms.valueOf(algorithm);
    return switch (stdAlgo) {
      case BLAKE2B_256 -> BLAKE2B_256;
      case BLAKE2B_512 -> BLAKE2B_512;
      case BLAKE2S_256 -> BLAKE2S_256;
      case BLAKE3_256 -> BLAKE3_256;
      case BLAKE3_512 -> BLAKE3_512;
      case SHA2_256 -> SHA2_256;
      case SHA2_512 -> SHA2_512;
      case SHA3_256 -> SHA3_256;
      case SHA3_512 -> SHA3_512;
    };
  }

  Digest digest(byte[] bytes);

  static boolean matches(byte[] bytes, Digest d1) {
    return Arrays.equals(
        d1.bytes(),
        lookup(d1.algorithm()).digest(bytes).bytes());
  }

}
