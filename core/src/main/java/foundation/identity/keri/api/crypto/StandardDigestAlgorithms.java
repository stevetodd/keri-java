package foundation.identity.keri.api.crypto;

public enum StandardDigestAlgorithms implements DigestAlgorithm {
  BLAKE2B_256("BLAKE2B-256", 32),
  BLAKE2B_512("BLAKE2B-512", 64),
  BLAKE2S_256("BLAKE2S-256", 32),
  BLAKE3_256("BLAKE3-256", 32),
  BLAKE3_512("BLAKE3-512", 64),
  SHA2_256("SHA-256", 32),
  SHA2_512("SHA-512", 64),
  SHA3_256("SHA3-256", 32),
  SHA3_512("SHA3-512", 64);

  public static StandardDigestAlgorithms DEFAULT = BLAKE3_256;

  final String algorithmName;
  final int digestLength;

  StandardDigestAlgorithms(String algorithmName, int digestLength) {
    this.algorithmName = algorithmName;
    this.digestLength = digestLength;
  }

  public static StandardDigestAlgorithms valueOf(DigestAlgorithm algorithm) {
    if (algorithm instanceof StandardDigestAlgorithms) {
      return (StandardDigestAlgorithms) algorithm;
    }

    for (var v : values()) {
      if (v.algorithmName().equals(algorithm.algorithmName())) {
        return v;
      }
    }

    throw new IllegalArgumentException("No algorithm with name " + algorithm.algorithmName());
  }

  @Override
  public int digestLength() {
    return this.digestLength;
  }

  @Override
  public String algorithmName() {
    return this.algorithmName;
  }

}
