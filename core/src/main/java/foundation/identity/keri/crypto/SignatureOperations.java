package foundation.identity.keri.crypto;

import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.crypto.SignatureAlgorithm;
import foundation.identity.keri.api.crypto.StandardSignatureAlgorithms;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public interface SignatureOperations {

  EcDSAOperations EC_SECP256K1 = new EcDSAOperations(StandardSignatureAlgorithms.EC_SECP256K1);
  EdDSAOperations ED_25519 = new EdDSAOperations(StandardSignatureAlgorithms.ED_25519);
  EdDSAOperations ED_448 = new EdDSAOperations(StandardSignatureAlgorithms.ED_448);

  static SignatureOperations lookup(SignatureAlgorithm algorithm) {
    var stdAlgo = StandardSignatureAlgorithms.valueOf(algorithm);
    return switch (stdAlgo) {
      case EC_SECP256K1 -> EC_SECP256K1;
      case ED_25519 -> ED_25519;
      case ED_448 -> ED_448;
    };
  }

  static SignatureOperations lookup(PublicKey publicKey) {
    return lookup(StandardSignatureAlgorithms.lookup(publicKey));
  }

  static SignatureOperations lookup(PrivateKey privateKey) {
    return lookup(StandardSignatureAlgorithms.lookup(privateKey));
  }

  KeyPair generateKeyPair();

  KeyPair generateKeyPair(SecureRandom secureRandom);

  byte[] encode(PublicKey publicKey);

  PublicKey publicKey(byte[] bytes);

  PrivateKey privateKey(byte[] bytes);

  default KeyPair keyPair(byte[] bytes, byte[] publicKey) {
    return new KeyPair(publicKey(publicKey), privateKey(bytes));
  }

  Signature signature(byte[] signatureBytes);

  Signature sign(byte[] message, PrivateKey privateKey);

  boolean verify(byte[] message, Signature signature, PublicKey publicKey);

}
