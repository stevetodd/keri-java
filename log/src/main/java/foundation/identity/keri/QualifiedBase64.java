package foundation.identity.keri;

import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;
import foundation.identity.keri.api.identifier.SelfSigningIdentifier;
import foundation.identity.keri.crypto.Digest;
import foundation.identity.keri.crypto.DigestAlgorithm;
import foundation.identity.keri.crypto.ImmutableDigest;
import foundation.identity.keri.crypto.Signature;
import foundation.identity.keri.crypto.SignatureAlgorithm;
import foundation.identity.keri.crypto.StandardSignatureAlgorithms;
import foundation.identity.keri.internal.identifier.ImmutableBasicIdentifier;
import foundation.identity.keri.internal.identifier.ImmutableSelfAddressingIdentifier;
import foundation.identity.keri.internal.identifier.ImmutableSelfSigningIdentifier;
import org.bouncycastle.util.Arrays;

import java.security.PublicKey;
import java.util.Base64;

import static foundation.identity.keri.crypto.SignatureOperations.*;
import static foundation.identity.keri.crypto.StandardDigestAlgorithms.*;

public final class QualifiedBase64 {

  private static final Base64.Encoder BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder BASE64_DECODER = Base64.getUrlDecoder();

  private static final char[] BASE64_LOOKUP = {
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
      'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
      'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
  };

  private static final int[] BASE64_REVERSE_LOOKUP;

  static {
    BASE64_REVERSE_LOOKUP = new int[128];
    Arrays.fill(BASE64_REVERSE_LOOKUP, 0xff);
    for (var i = 0; i < BASE64_LOOKUP.length; i++) {
      BASE64_REVERSE_LOOKUP[BASE64_LOOKUP[i]] = i;
    }
  }

  private QualifiedBase64() {
    throw new IllegalStateException("Do not instantiate.");
  }

  public static String base64(byte[] b) {
    return BASE64_ENCODER.encodeToString(b);
  }

  public static String base64(int i) {
    return base64(i, 0);
  }

  public static String base64(int i, int paddedLength) {
    var base64 = new StringBuilder(6);

    do {
      base64.append(BASE64_LOOKUP[i % 64]);
      i /= 64;
      paddedLength--;
    } while (i > 0 || paddedLength > 0);

    return base64.reverse().toString();
  }

  public static byte[] unbase64(String base64) {
    return BASE64_DECODER.decode(base64);
  }

  public static int unbase64Int(String base64) {
    var chars = base64.toCharArray();
    var result = 0;
    for (var i = 0; i < chars.length; i++) {
      result += BASE64_REVERSE_LOOKUP[chars[i]] << (6 * (chars.length - i - 1));
    }
    return result;
  }

  public static String identifierPlaceholder(Identifier identifier) {
    if (identifier instanceof BasicIdentifier) {
      var bp = (BasicIdentifier) identifier;
      var signatureAlgorithm = StandardSignatureAlgorithms.lookup(bp.publicKey());
      return basicIdentifierPlaceholder(signatureAlgorithm);
    } else if (identifier instanceof SelfAddressingIdentifier) {
      var sap = (SelfAddressingIdentifier) identifier;
      return selfAddressingIdentifierPlaceholder(sap.digest().algorithm());
    } else if (identifier instanceof SelfSigningIdentifier) {
      var ssp = (SelfSigningIdentifier) identifier;
      return selfSigningIdentifierPlaceholder(ssp.signature().algorithm());
    } else {
      throw new IllegalArgumentException("unknown prefix type: " + identifier.getClass().getCanonicalName());
    }
  }

  public static String basicIdentifierPlaceholder(SignatureAlgorithm signatureAlgorithm) {
    var placeholderLength = qb64Length(signatureAlgorithm.publicKeyLength());
    return "#".repeat(placeholderLength);
  }

  public static String selfAddressingIdentifierPlaceholder(DigestAlgorithm digestAlgorithm) {
    var placeholderLength = qb64Length(digestAlgorithm.digestLength());
    return "#".repeat(placeholderLength);
  }

  public static String selfSigningIdentifierPlaceholder(SignatureAlgorithm signatureAlgorithm) {
    var placeholderLength = qb64Length(signatureAlgorithm.signatureLength());
    return "#".repeat(placeholderLength);
  }

  public static int base64Length(int bytesLength) {
    var bits = bytesLength * 8;
    return bits / 6
        + (bits % 6 != 0 ? 1 : 0);
  }

  public static int qb64Length(int materialLength) {
    var bits = materialLength * 8;
    return bits / 6
        + (bits % 6 != 0 ? 1 : 0)
        + (bits % 6 != 0 ? (6 - bits % 6) / 2 : 0)
        // if no padding, then we add 4 to accomodate code
        + (bits % 6 == 0 ? 4 : 0);
  }

  public static String qb64(Digest d) {
    return digestCode(d.algorithm()) + base64(d.bytes());
  }

  public static String digestCode(DigestAlgorithm algorithm) {
    var stdAlg = valueOf(algorithm);
    return switch (stdAlg) {
      case BLAKE2B_256 -> "F";
      case BLAKE2B_512 -> "0F";
      case BLAKE2S_256 -> "G";
      case BLAKE3_256 -> "E";
      case BLAKE3_512 -> "0D";
      case SHA2_256 -> "I";
      case SHA2_512 -> "0G";
      case SHA3_256 -> "H";
      case SHA3_512 -> "0E";
    };
  }

  public static String qb64(Signature s) {
    return signatureCode(s.algorithm()) + base64(s.bytes());
  }

  public static String signatureCode(SignatureAlgorithm algorithm) {
    var stdAlgo = StandardSignatureAlgorithms.valueOf(algorithm);
    return switch (stdAlgo) {
      case ED_25519 -> "0B";
      case EC_SECP256K1 -> "0C";
      case ED_448 -> "1AAE";
    };
  }

  public static SignatureAlgorithm signatureAlgorithm(String code) {
    return switch (code) {
      case "0B" -> StandardSignatureAlgorithms.ED_25519;
      case "0C" -> StandardSignatureAlgorithms.EC_SECP256K1;
      case "1AAE" -> StandardSignatureAlgorithms.ED_448;
      default -> throw new IllegalArgumentException("unknown code: " + code);
    };
  }

  public static String attachedSignatureCode(SignatureAlgorithm algorithm, int index) {
    var stdAlgo = StandardSignatureAlgorithms.valueOf(algorithm);
    return switch (stdAlgo) {
      case ED_25519 -> "A" + base64(index, 1);
      case EC_SECP256K1 -> "B" + base64(index, 1);
      case ED_448 -> "0A" + base64(index, 2);
    };
  }

  public static StandardSignatureAlgorithms attachedSignatureAlgorithm(String code) {
    return switch (code.charAt(0)) {
      case 'A' -> StandardSignatureAlgorithms.ED_25519;
      case 'B' -> StandardSignatureAlgorithms.EC_SECP256K1;
      case '0' -> switch (code.charAt(1)) {
        case 'A' -> StandardSignatureAlgorithms.EC_SECP256K1;
        default -> throw new IllegalArgumentException("unknown code: " + code);
      };
      default -> throw new IllegalArgumentException("unknown code: " + code);
    };
  }

  public static String qb64(PublicKey publicKey) {
    var stdAlgo = StandardSignatureAlgorithms.lookup(publicKey);
    var sigOps = lookup(publicKey);
    return publicKeyCode(stdAlgo) + base64(sigOps.encode(publicKey));
  }

  public static String publicKeyCode(SignatureAlgorithm a) {
    var stdAlgo = StandardSignatureAlgorithms.valueOf(a);
    return switch (stdAlgo) {
      case EC_SECP256K1 -> "1AAB";
      case ED_25519 -> "D";
      case ED_448 -> "1AAD";
    };
  }

  public static StandardSignatureAlgorithms publicKeyAlgorithm(String code) {
    return switch (code) {
      case "1AAB" -> StandardSignatureAlgorithms.EC_SECP256K1;
      case "D" -> StandardSignatureAlgorithms.ED_25519;
      case "1AAD" -> StandardSignatureAlgorithms.ED_448;
      default -> throw new IllegalArgumentException("unknown code: " + code);
    };
  }

  public static PublicKey publicKey(String qb64) {
    if (qb64.startsWith("1")) {
      var bytes = unbase64(qb64.substring(4));
      return switch (qb64.substring(1, 4)) {
        case "AAB" -> EC_SECP256K1.publicKey(bytes);
        case "AAD" -> ED_448.publicKey(bytes);
        default -> throw new RuntimeException("Unrecognized public key: " + qb64);
      };
    } else if (!qb64.matches("^[0-6-]")) {
      var bytes = unbase64(qb64.substring(1));
      return switch (qb64.substring(0, 1)) {
        case "D" -> ED_25519.publicKey(bytes);
        default -> throw new RuntimeException("Unrecognized public key: " + qb64);
      };
    } else {
      throw new RuntimeException("Unrecognized public key: " + qb64);
    }
  }

  public static Identifier identifier(String qb64) {
    if (qb64.startsWith("0")) {
      var bytes = unbase64(qb64.substring(2));
      return switch (qb64.substring(1, 2)) {
        // case "A" -> null; // Random seed or private key of length 128 bits
        case "B" -> new ImmutableSelfSigningIdentifier(ED_25519.signature(bytes));
        case "C" -> new ImmutableSelfSigningIdentifier(EC_SECP256K1.signature(bytes));
        case "D" -> new ImmutableSelfAddressingIdentifier(new ImmutableDigest(BLAKE3_512, bytes));
        case "E" -> new ImmutableSelfAddressingIdentifier(new ImmutableDigest(SHA3_512, bytes));
        case "F" -> new ImmutableSelfAddressingIdentifier(new ImmutableDigest(BLAKE2B_512, bytes));
        case "G" -> new ImmutableSelfAddressingIdentifier(new ImmutableDigest(SHA2_512, bytes));
        default -> throw new RuntimeException("Unrecognized identifier: " + qb64);
      };
    } else if (qb64.startsWith("1")) {
      var bytes = unbase64(qb64.substring(4));
      return switch (qb64.substring(1, 4)) {
        case "AAA" -> new ImmutableBasicIdentifier(EC_SECP256K1.publicKey(bytes));
        // case "AAB" -> null; // EC SECP256K1 public key
        case "AAC" -> new ImmutableBasicIdentifier(ED_448.publicKey(bytes));
        // case "AAD" -> null; // Ed448 public key
        case "AAE" -> new ImmutableSelfSigningIdentifier(ED_25519.signature(bytes));
        default -> throw new RuntimeException("Unrecognized identifier: " + qb64);
      };
    } else if (!qb64.matches("^[0-6-]")) {
      var bytes = unbase64(qb64.substring(1));
      return switch (qb64.substring(0, 1)) {
        // case "A" -> null; // Random seed of Ed25519 private key of length 256 bits
        case "B" -> new ImmutableBasicIdentifier(ED_25519.publicKey(bytes));
        // case "C" -> null; // X25519 public encryption key
        // case "D" -> null; // Ed25519 public signing verification key.
        case "E" -> new ImmutableSelfAddressingIdentifier(new ImmutableDigest(BLAKE3_256, bytes));
        case "F" -> new ImmutableSelfAddressingIdentifier(new ImmutableDigest(BLAKE2B_256, bytes));
        case "G" -> new ImmutableSelfAddressingIdentifier(new ImmutableDigest(BLAKE2S_256, bytes));
        case "H" -> new ImmutableSelfAddressingIdentifier(new ImmutableDigest(SHA3_256, bytes));
        case "I" -> new ImmutableSelfAddressingIdentifier(new ImmutableDigest(SHA2_256, bytes));
        default -> throw new RuntimeException("Unrecognized identifier: " + qb64);
      };
    } else {
      throw new RuntimeException("Unrecognized identifier: " + qb64);
    }
  }

  public static StandardSignatureAlgorithms basicIdentifierSignatureAlgorithm(String code) {
    return switch (code) {
      case "1AAA" -> StandardSignatureAlgorithms.EC_SECP256K1;
      case "1AAC" -> StandardSignatureAlgorithms.ED_25519;
      case "B" -> StandardSignatureAlgorithms.ED_448;
      default -> throw new IllegalArgumentException("unknown code: " + code);
    };
  }

  public static Digest digest(String qb64) {
    if (qb64.startsWith("0")) {
      var bytes = unbase64(qb64.substring(2));
      return switch (qb64.substring(1, 2)) {
        case "D" -> new ImmutableDigest(BLAKE3_512, bytes);
        case "E" -> new ImmutableDigest(SHA3_512, bytes);
        case "F" -> new ImmutableDigest(BLAKE2B_512, bytes);
        case "G" -> new ImmutableDigest(SHA2_512, bytes);
        default -> throw new RuntimeException("Unrecognized digest: " + qb64);
      };
    } else if (!qb64.matches("^[0-6-]")) {
      var bytes = unbase64(qb64.substring(1));
      return switch (qb64.substring(0, 1)) {
        case "E" -> new ImmutableDigest(BLAKE3_256, bytes);
        case "F" -> new ImmutableDigest(BLAKE2B_256, bytes);
        case "G" -> new ImmutableDigest(BLAKE2S_256, bytes);
        case "H" -> new ImmutableDigest(SHA3_256, bytes);
        case "I" -> new ImmutableDigest(SHA2_256, bytes);
        default -> throw new RuntimeException("Unrecognized digest: " + qb64);
      };
    } else {
      throw new RuntimeException("Unrecognized digest: " + qb64);
    }
  }

  public static Signature signature(String qb64) {
    if (qb64.startsWith("0")) {
      var bytes = unbase64(qb64.substring(2));
      return switch (qb64.substring(1, 2)) {
        case "B" -> ED_25519.signature(bytes);
        case "C" -> EC_SECP256K1.signature(bytes);
        default -> throw new RuntimeException("Unrecognized signature: " + qb64);
      };
    } else if (qb64.startsWith("1")) {
      var bytes = unbase64(qb64.substring(4));
      return switch (qb64.substring(1, 4)) {
        case "AAE" -> ED_448.signature(bytes);
        default -> throw new RuntimeException("Unrecognized signature: " + qb64);
      };
    } else {
      throw new RuntimeException("Unrecognized signature: " + qb64);
    }
  }

  public static String qb64(Identifier identifier) {
    if (identifier instanceof BasicIdentifier) {
      return qb64((BasicIdentifier) identifier);
    } else if ((identifier instanceof SelfAddressingIdentifier)) {
      return qb64((SelfAddressingIdentifier) identifier);
    } else if (identifier instanceof SelfSigningIdentifier) {
      return qb64((SelfSigningIdentifier) identifier);
    }

    throw new RuntimeException("Unrecognized identifier: " + identifier.getClass());
  }

  public static String qb64(BasicIdentifier identifier) {
    var stdAlgo = StandardSignatureAlgorithms.lookup(identifier.publicKey());
    var sigOps = lookup(identifier.publicKey());
    return nonTransferrableIdentifierCode(stdAlgo) + base64(sigOps.encode(identifier.publicKey()));
  }

  public static String qb64(SelfAddressingIdentifier identifier) {
    return qb64(identifier.digest());
  }

  public static String qb64(SelfSigningIdentifier identifier) {
    return qb64(identifier.signature());
  }

  public static String transferrableIdentifierCode(SignatureAlgorithm a) {
    return publicKeyCode(a);
  }

  public static String nonTransferrableIdentifierCode(SignatureAlgorithm a) {
    var stdAlgo = StandardSignatureAlgorithms.valueOf(a);
    return switch (stdAlgo) {
      case EC_SECP256K1 -> "1AAA";
      case ED_25519 -> "B";
      case ED_448 -> "1AAC";
    };
  }

}
