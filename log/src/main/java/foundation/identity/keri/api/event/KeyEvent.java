package foundation.identity.keri.api.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.Digest;
import foundation.identity.keri.crypto.Signature;

import java.util.Map;

public interface KeyEvent {

  byte[] bytes();

  Version version();

  Format format();

  default Identifier identifier() {
    return this.coordinates().identifier();
  }

  default long sequenceNumber() {
    return this.coordinates().sequenceNumber();
  }

  default Digest digest() {
    return this.coordinates().digest();
  }

  KeyEventCoordinates coordinates();

  KeyEventCoordinates previous();

  // attachments

  Map<Integer, Signature> authentication();

  Map<Integer, Signature> endorsements();

  Map<KeyEventCoordinates, Map<Integer, Signature>> receipts();

}
