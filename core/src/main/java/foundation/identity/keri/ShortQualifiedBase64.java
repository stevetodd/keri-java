package foundation.identity.keri;


import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.identifier.Identifier;

import java.security.PublicKey;

import static foundation.identity.keri.QualifiedBase64.qb64;

/**
 * Provides shortened representations of {@link QualifiedBase64}. Useful for logging, for example,
 * but not much else since the code cannot be resolved to it's full length.
 */
public class ShortQualifiedBase64 {

  public final static int SHORTENED_LENGTH = 12;

  public static String shortQb64(PublicKey publicKey) {
    return qb64(publicKey).substring(0, SHORTENED_LENGTH);
  }

  public static String shortQb64(Digest digest) {
    return qb64(digest).substring(0, SHORTENED_LENGTH);
  }

  public static String shortQb64(Signature signature) {
    return qb64(signature).substring(0, SHORTENED_LENGTH);
  }

  public static String shortQb64(Identifier identifier) {
    return qb64(identifier).substring(0, SHORTENED_LENGTH);
  }

}
