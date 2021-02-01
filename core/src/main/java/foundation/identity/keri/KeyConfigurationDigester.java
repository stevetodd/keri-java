package foundation.identity.keri;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.internal.crypto.ImmutableDigest;
import foundation.identity.keri.internal.event.ImmutableKeyConfigurationDigest;

import java.security.PublicKey;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;

public class KeyConfigurationDigester {

  public static KeyConfigurationDigest digest(int signingThreshold, List<PublicKey> nextKeys, DigestAlgorithm algo) {
    var digOps = DigestOperations.lookup(algo);

    var keyDigs = nextKeys.stream()
        .map(QualifiedBase64::qb64)
        .map(qb64 -> qb64.getBytes(UTF_8))
        .map(digOps::digest)
        .collect(toList());

    return digest(signingThreshold, keyDigs);
  }

  public static KeyConfigurationDigest digest(int signingThreshold, List<Digest> nextKeyDigests) {
    var st = Hex.hexNoPad(signingThreshold).getBytes(UTF_8);
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
}
