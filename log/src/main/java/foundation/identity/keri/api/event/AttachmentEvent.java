package foundation.identity.keri.api.event;

import foundation.identity.keri.crypto.Signature;

import java.util.Map;

public interface AttachmentEvent {

  KeyEventCoordinates coordinates();

  Map<Integer, Signature> authentication();

  Map<Integer, Signature> endorsements();

  Map<KeyEventCoordinates, Map<Integer, Signature>> receipts();

}
