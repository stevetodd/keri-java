package foundation.identity.keri.controller;

import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;
import foundation.identity.keri.api.identifier.SelfSigningIdentifier;
import foundation.identity.keri.controller.spec.IdentifierSpec;
import foundation.identity.keri.controller.spec.Signer;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.internal.identifier.ImmutableBasicIdentifier;
import foundation.identity.keri.internal.identifier.ImmutableSelfAddressingIdentifier;
import foundation.identity.keri.internal.identifier.ImmutableSelfSigningIdentifier;

import java.security.PublicKey;

public class IdentifierFactory {

  public static Identifier identifier(IdentifierSpec spec, byte[] inceptionStatement) {
    Class<? extends Identifier> derivation = spec.derivation();
    if (derivation.isAssignableFrom(BasicIdentifier.class)) {
      return basic(spec.keys().get(0));
    } else if (derivation.isAssignableFrom(SelfAddressingIdentifier.class)) {
      return selfAddressing(inceptionStatement, spec.selfAddressingDigestAlgorithm());
    } else if (derivation.isAssignableFrom(SelfSigningIdentifier.class)) {
      return selfSigning(inceptionStatement, spec.signer());
    } else {
      throw new IllegalArgumentException("unknown prefix type: " + derivation.getCanonicalName());
    }
  }

  public static BasicIdentifier basic(PublicKey key) {
    return new ImmutableBasicIdentifier(key);
  }

  public static SelfAddressingIdentifier selfAddressing(byte[] inceptionStatement, DigestAlgorithm digestAlgorithm) {
    var digOps = DigestOperations.lookup(digestAlgorithm);
    var digest = digOps.digest(inceptionStatement);
    return new ImmutableSelfAddressingIdentifier(digest);
  }

  public static SelfSigningIdentifier selfSigning(byte[] inceptionStatement, Signer signer) {
    var signature = signer.sign(inceptionStatement);
    return new ImmutableSelfSigningIdentifier(signature);
  }

}
