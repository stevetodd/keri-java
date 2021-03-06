package foundation.identity.keri;


import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.Digest;
import foundation.identity.keri.crypto.Signature;

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

  public static String shortQb64(KeyEventCoordinates c) {
    return shortQb64(c.identifier()) + ":" + c.sequenceNumber() + ":" + shortQb64(c.digest());
  }

  public static String shortQb64(DelegatingEventCoordinates c) {
    var p = c.previousEvent();
    return shortQb64(p.identifier()) + ":" + p.sequenceNumber() + ":" + shortQb64(p.digest());
  }

}
