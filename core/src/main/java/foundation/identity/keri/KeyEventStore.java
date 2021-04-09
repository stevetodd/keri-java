package foundation.identity.keri;

import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.ReceiptEvent;
import foundation.identity.keri.api.event.SealingEvent;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Optional;
import java.util.stream.Stream;

public interface KeyEventStore {

  void append(IdentifierEvent event);

  void append(ReceiptEvent event);

  Optional<SealingEvent> getKeyEvent(DelegatingEventCoordinates coordinates);

  Optional<IdentifierEvent> getKeyEvent(IdentifierEventCoordinatesWithDigest coordinates);

  Stream<IdentifierEvent> streamKeyEvents(Identifier identifier);

  Stream<IdentifierEvent> streamKeyEvents(Identifier identifier, BigInteger from);

  Optional<KeyState> getKeyState(Identifier identifier);

  Optional<KeyState> getKeyState(IdentifierEventCoordinatesWithDigest previous);

  Optional<EventSignature> findLatestReceipt(Identifier forIdentifier, Identifier byIdentifier);
}
