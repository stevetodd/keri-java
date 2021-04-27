package foundation.identity.keri.crypto;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECPointUtil;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class EcDSAOperations implements SignatureOperations {

  static final String ECDSA_ALGORITHM_NAME = "EC";
  static final String ECDSA_SIGNATURE_ALGORITHM_SUFFIX = "withECDSA";

  final SignatureAlgorithm signatureAlgorithm;
  final ECParameterSpec parameterSpec;
  final KeyPairGenerator keyPairGenerator;
  final KeyFactory keyFactory;

  public EcDSAOperations(SignatureAlgorithm signatureAlgorithm) {
    try {
      this.signatureAlgorithm = signatureAlgorithm;

      var ap = AlgorithmParameters.getInstance(ECDSA_ALGORITHM_NAME);
      ap.init(new ECGenParameterSpec(((EcDSAParameters) signatureAlgorithm.parameters()).curveName()));
      this.parameterSpec = ap.getParameterSpec(ECParameterSpec.class);

      this.keyPairGenerator = KeyPairGenerator.getInstance(ECDSA_ALGORITHM_NAME);
      this.keyPairGenerator.initialize(this.parameterSpec);
      this.keyFactory = KeyFactory.getInstance(ECDSA_ALGORITHM_NAME);
    } catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public KeyPair generateKeyPair() {
    return this.keyPairGenerator.generateKeyPair();
  }

  @Override
  public KeyPair generateKeyPair(SecureRandom secureRandom) {
    try {
      var keyPairGenerator = KeyPairGenerator.getInstance(ECDSA_ALGORITHM_NAME);
      keyPairGenerator.initialize(this.parameterSpec, secureRandom);
      return keyPairGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] encode(PublicKey publicKey) {
    try {
      // TODO remove bouncycastle dependency--used here to support compression
      var publicKeyParameter = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(publicKey);
      return publicKeyParameter.getQ().getEncoded(true);
    } catch (GeneralSecurityException e) {
      // TODO handle better
      throw new RuntimeException(e);
    }
  }

  @Override
  public PublicKey publicKey(byte[] bytes) {
    try {
      // TODO remove bouncycastle dependency--used here to support compression
      var ecPoint = ECPointUtil.decodePoint(this.parameterSpec.getCurve(), bytes);
      var spec = new ECPublicKeySpec(ecPoint, this.parameterSpec);

      return this.keyFactory.generatePublic(spec);
    } catch (GeneralSecurityException e) {
      // TODO handle better
      throw new RuntimeException(e);
    }
  }

  @Override
  public PrivateKey privateKey(byte[] bytes) {
    try {
      var spec = new ECPrivateKeySpec(new BigInteger(1, bytes), this.parameterSpec);

      return this.keyFactory.generatePrivate(spec);
    } catch (InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public Signature signature(byte[] signatureBytes) {
    return new ImmutableSignature(StandardSignatureAlgorithms.EC_SECP256K1, signatureBytes);
  }

  @Override
  public Signature sign(byte[] message, PrivateKey privateKey) {
    try {
      var parameters = (EcDSAParameters) this.signatureAlgorithm.parameters();
      var sig = java.security.Signature.getInstance(this.signatureInstanceName(parameters));
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
      var parameters = (EcDSAParameters) this.signatureAlgorithm.parameters();
      var sig = java.security.Signature.getInstance(this.signatureInstanceName(parameters));
      sig.initVerify(publicKey);
      sig.update(message);
      return sig.verify(signature.bytes());
    } catch (GeneralSecurityException e) {
      // TODO handle better
      throw new RuntimeException(e);
    }
  }

  private String signatureInstanceName(EcDSAParameters parameters) {
    return parameters.digestAlgorithm() + ECDSA_SIGNATURE_ALGORITHM_SUFFIX;
  }

}
