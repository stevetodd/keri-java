package foundation.identity.keri;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.event.SigningThreshold.Weighted.Weight;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.internal.crypto.ImmutableDigest;
import foundation.identity.keri.internal.event.ImmutableKeyConfigurationDigest;

import java.security.PublicKey;
import java.util.List;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;

public class KeyConfigurationDigester {

  public static boolean matches(SigningThreshold signingThreshold, List<PublicKey> nextKeys, KeyConfigurationDigest in) {
    return digest(signingThreshold, nextKeys, in.algorithm()).equals(in);
  }

  public static KeyConfigurationDigest digest(SigningThreshold signingThreshold, List<PublicKey> nextKeys, DigestAlgorithm algo) {
    var digOps = DigestOperations.lookup(algo);

    var keyDigs = nextKeys.stream()
        .map(QualifiedBase64::qb64)
        .map(qb64 -> qb64.getBytes(UTF_8))
        .map(digOps::digest)
        .collect(toList());

    return digest(signingThreshold, keyDigs);
  }

  public static KeyConfigurationDigest digest(SigningThreshold signingThreshold, List<Digest> nextKeyDigests) {
    var st = signingThresholdRepresentation(signingThreshold);
    var digestAlgorithm = nextKeyDigests.get(0).algorithm();
    var digOps = DigestOperations.lookup(digestAlgorithm);

    var digest = digOps.digest(st).bytes();// digest
    for (var d : nextKeyDigests) {
      var keyDigest = d.bytes();
      for (var i = keyDigest.length - 1; i >= 0; i--) {
        digest[i] = (byte) (digest[i] ^ keyDigest[i]);
      }
    }

    return new ImmutableKeyConfigurationDigest(new ImmutableDigest(nextKeyDigests.get(0).algorithm(), digest));
  }

  static byte[] signingThresholdRepresentation(SigningThreshold threshold) {
    if (threshold instanceof SigningThreshold.Unweighted) {
      return Hex.hexNoPad(((SigningThreshold.Unweighted) threshold).threshold()).getBytes(UTF_8);
    } else if (threshold instanceof SigningThreshold.Weighted) {
      return Stream.of(((SigningThreshold.Weighted) threshold).weights())
          .map(lw -> Stream.of(lw)
              .map(KeyConfigurationDigester::weight)
              .collect(joining(",")))
          .collect(joining(("&")))
          .getBytes(UTF_8);
    } else {
      throw new IllegalArgumentException("Unknown threshold type: " + threshold.getClass());
    }
  }

  static String weight(Weight w) {
    if (w.denominator().isEmpty()) {
      return "" + w.numerator();
    }

    return w.numerator() + "/" + w.denominator().get();
  }

}
