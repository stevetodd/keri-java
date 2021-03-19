package foundation.identity.keri.api.event;

public interface ReceiptEvent extends Event {

  IdentifierEventCoordinatesWithDigest event();

}
