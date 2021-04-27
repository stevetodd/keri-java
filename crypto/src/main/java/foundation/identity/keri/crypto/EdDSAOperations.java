package foundation.identity.keri.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

public class EdDSAOperations implements SignatureOperations {

  private static final String EDDSA_ALGORITHM_NAME = "EdDSA";

  final SignatureAlgorithm signatureAlgorithm;
  final NamedParameterSpec parameterSpec;
  final KeyPairGenerator keyPairGenerator;
  final KeyFactory keyFactory;

  public EdDSAOperations(SignatureAlgorithm signatureAlgorithm) {
    try {
      this.signatureAlgorithm = signatureAlgorithm;

      var curveName = ((EdDSAParameters) signatureAlgorithm.parameters()).curveName().toLowerCase();
      this.parameterSpec = switch (curveName) {
        case "ed25519" -> NamedParameterSpec.ED25519;
        case "ed448" -> NamedParameterSpec.ED448;
        default -> throw new RuntimeException("Unknown Edwards curve: " + curveName);
      };

      this.keyPairGenerator = KeyPairGenerator.getInstance(EDDSA_ALGORITHM_NAME);
      this.keyPairGenerator.initialize(this.parameterSpec);
      this.keyFactory = KeyFactory.getInstance(EDDSA_ALGORITHM_NAME);
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  private static EdECPoint decodeEdPoint(byte[] in) {
    var arr = in.clone();
    var msb = arr[arr.length - 1];
    arr[arr.length - 1] &= (byte) 0x7F;
    var xOdd = (msb & 0x80) != 0;
    reverse(arr);
    var y = new BigInteger(1, arr);
    return new EdECPoint(xOdd, y);
  }

  private static void swap(byte[] arr, int i, int j) {
    var tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }

  private static void reverse(byte[] arr) {
    var i = 0;
    var j = arr.length - 1;

    while (i < j) {
      swap(arr, i, j);
      i++;
      j--;
    }
  }

  @Override
  public KeyPair generateKeyPair() {
    return this.keyPairGenerator.generateKeyPair();
  }

  @Override
  public KeyPair generateKeyPair(SecureRandom secureRandom) {
    try {
      var kpg = KeyPairGenerator.getInstance(EDDSA_ALGORITHM_NAME);
      kpg.initialize(this.parameterSpec, secureRandom);
      return kpg.generateKeyPair();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] encode(PublicKey publicKey) {
    var point = ((EdECPublicKey) publicKey).getPoint();
    var encodedPoint = point.getY().toByteArray();

    reverse(encodedPoint);
    encodedPoint = Arrays.copyOf(encodedPoint, this.keyLength());
    var msb = (byte) (point.isXOdd() ? 0x80 : 0);
    encodedPoint[encodedPoint.length - 1] |= msb;

    return encodedPoint;
  }

  private int keyLength() {
    if (this.parameterSpec.getName().equals("Ed25519")) {
      return StandardSignatureAlgorithms.ED_25519.publicKeyLength();
    } else if (this.parameterSpec.getName().equals("Ed448")) {
      return StandardSignatureAlgorithms.ED_448.publicKeyLength();
    } else {
      // TODO handle better
      throw new RuntimeException("Unknown Edwards curve: " + this.parameterSpec.getName());
    }
  }

  @Override
  public PublicKey publicKey(byte[] bytes) {
    try {
      if (bytes.length != this.keyLength()) {
        throw new RuntimeException(new InvalidKeyException("key length is " + bytes.length +
            ", key length must be " + this.keyLength()));
      }

      var point = decodeEdPoint(bytes);

      return this.keyFactory.generatePublic(new EdECPublicKeySpec(this.parameterSpec, point));
    } catch (GeneralSecurityException e) {
      // TODO handle better
      throw new RuntimeException(e);
    }
  }

  @Override
  public PrivateKey privateKey(byte[] bytes) {
    try {

      return this.keyFactory.generatePrivate(new EdECPrivateKeySpec(this.parameterSpec, bytes));
    } catch (GeneralSecurityException e) {
      // TODO handle better
      throw new RuntimeException(e);
    }
  }

  @Override
  public Signature signature(byte[] signatureBytes) {
    return new ImmutableSignature(this.signatureAlgorithm, signatureBytes);
  }

  @Override
  public Signature sign(byte[] message, PrivateKey privateKey) {
    try {
      var sig = java.security.Signature.getInstance(EDDSA_ALGORITHM_NAME);
      sig.initSign(privateKey);
      sig.update(message);
      var bytes = sig.sign();

      return new ImmutableSignature(this.signatureAlgorithm, bytes);
    } catch (GeneralSecurityException e) {
      // TODO handle better
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean verify(byte[] message, Signature signature, PublicKey publicKey) {
    try {
      var sig = java.security.Signature.getInstance(EDDSA_ALGORITHM_NAME);
      sig.initVerify(publicKey);
      sig.update(message);
      return sig.verify(signature.bytes());
    } catch (GeneralSecurityException e) {
      // TODO handle better
      throw new RuntimeException(e);
    }
  }

}
