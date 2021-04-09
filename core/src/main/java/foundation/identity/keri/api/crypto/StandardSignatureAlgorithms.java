package foundation.identity.keri.api.crypto;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;

public enum StandardSignatureAlgorithms implements SignatureAlgorithm {
  EC_SECP256K1(BaseAlgorithm.EC, EcCurve.SECP256K1, 32, 33, 64),
  ED_25519(BaseAlgorithm.ED, EdCurve.ED25519, 32, 32, 64),
  ED_448(BaseAlgorithm.ED, EdCurve.ED448, 56, 57, 114);

  private final BaseAlgorithm algorithm;
  private final SignatureAlgorithmParameters parameters;
  private final int privateKeyLength;
  private final int publicKeyLength;
  private final int signatureLength;

  StandardSignatureAlgorithms(BaseAlgorithm algorithm, SignatureAlgorithmParameters parameters,
                              int privateKeyLength, int publicKeyLength, int signatureLength) {
    this.algorithm = algorithm;
    this.parameters = parameters;
    this.privateKeyLength = privateKeyLength;
    this.publicKeyLength = publicKeyLength;
    this.signatureLength = signatureLength;
  }

  public static StandardSignatureAlgorithms valueOf(SignatureAlgorithm algorithm) {
    if (algorithm instanceof StandardSignatureAlgorithms) {
      return (StandardSignatureAlgorithms) algorithm;
    }

    var baseAlgorithm = BaseAlgorithm.valueOf(algorithm.algorithmName());
    return switch (baseAlgorithm) {
      case EC -> {
        var parameters = (EcDSAParameters) algorithm.parameters();
        yield switch (parameters.curveName().toLowerCase()) {
          case "secp256k1" -> EC_SECP256K1;
          default -> throw new IllegalArgumentException("Unknown EC curve: " + parameters.curveName());
        };
      }
      case ED -> {
        var parameters = (EdDSAParameters) algorithm.parameters();
        yield switch (parameters.curveName().toLowerCase()) {
          case "ed25519" -> ED_25519;
          case "ed448" -> ED_448;
          default -> throw new IllegalArgumentException("Unknown EC curve: " + parameters.curveName());
        };
      }
    };
  }

  public static StandardSignatureAlgorithms lookup(PublicKey publicKey) {
    return switch (publicKey.getAlgorithm()) {
      case "EC" -> lookupEc(((ECPublicKey) publicKey).getParams());
      case "EdDSA" -> lookupEd(((EdECPublicKey) publicKey).getParams());
      case "Ed25519" -> ED_25519;
      case "Ed448" -> ED_448;
      default -> throw new IllegalArgumentException("Unknown algorithm: " + publicKey.getAlgorithm());
    };
  }

  public static StandardSignatureAlgorithms lookup(PrivateKey privateKey) {
    return switch (privateKey.getAlgorithm()) {
      case "EC" -> lookupEc(((ECPrivateKey) privateKey).getParams());
      case "EdDSA" -> lookupEd(((EdECPrivateKey) privateKey).getParams());
      case "Ed25519" -> ED_25519;
      case "Ed448" -> ED_448;
      default -> throw new IllegalArgumentException("Unknown algorithm: " + privateKey.getAlgorithm());
    };
  }

  private static StandardSignatureAlgorithms lookupEc(ECParameterSpec params) {
    try {
      var algorithmParameters = AlgorithmParameters.getInstance("EC");
      algorithmParameters.init(params);
      var genParamSpec = algorithmParameters.getParameterSpec(ECGenParameterSpec.class);
      var curveName = genParamSpec.getName();
      return switch (curveName.toLowerCase()) {
        case "1.3.132.0.10":
        case "secp256k1":
          yield EC_SECP256K1;
        default: throw new IllegalArgumentException("Unknown EC curve: " + curveName);
      };
    } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
      throw new IllegalStateException("EC algorithm or needed curves unavailable.", e);
    }
  }

  private static StandardSignatureAlgorithms lookupEd(NamedParameterSpec params) {
    var curveName = params.getName();
    return switch (curveName.toLowerCase()) {
      case "ed25519" -> ED_25519;
      case "ed448" -> ED_448;
      default -> throw new IllegalArgumentException("Unknown edwards curve: " + curveName);
    };
  }

  public BaseAlgorithm algorithm() {
    return this.algorithm;
  }

  @Override
  public String algorithmName() {
    return this.algorithm.name();
  }

  @Override
  public SignatureAlgorithmParameters parameters() {
    return this.parameters;
  }

  @Override
  public int privateKeyLength() {
    return this.privateKeyLength;
  }

  @Override
  public int publicKeyLength() {
    return this.publicKeyLength;
  }

  @Override
  public int signatureLength() {
    return this.signatureLength;
  }

  public enum BaseAlgorithm {
    EC, ED
  }

  public enum EcCurve implements EcDSAParameters {
    SECP256K1("SHA256", "secp256k1");

    private final String curveName;
    private final String signatureAlgorithm;

    EcCurve(String signatureAlgorithm, String curveName) {
      this.signatureAlgorithm = signatureAlgorithm;
      this.curveName = curveName;
    }

    @Override
    public String digestAlgorithm() {
      return this.signatureAlgorithm;
    }

    @Override
    public String curveName() {
      return this.curveName;
    }
  }

  public enum EdCurve implements EdDSAParameters {
    ED25519("ed25519"),
    ED448("ed448");

    private final String curveName;

    EdCurve(String curveName) {
      this.curveName = curveName;
    }

    @Override
    public String curveName() {
      return this.curveName;
    }
  }

}
