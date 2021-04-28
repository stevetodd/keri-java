package foundation.identity.keri.api.event;

import foundation.identity.keri.crypto.Signature;

import java.util.Map;

public interface SignatureThresholdAuthentication {

  Map<Integer, Signature> signatures();

}
