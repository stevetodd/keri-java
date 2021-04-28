package foundation.identity.keri;

import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.SealingEvent;
import foundation.identity.keri.api.identifier.Identifier;

import java.util.Optional;
import java.util.OptionalLong;
import java.util.stream.Stream;

public interface KeyEventStore {

  void append(KeyEvent event);

  void append(AttachmentEvent event);

  Optional<SealingEvent> getKeyEvent(DelegatingEventCoordinates coordinates);

  Optional<KeyEvent> getKeyEvent(KeyEventCoordinates coordinates);

  Stream<KeyEvent> streamKeyEvents(Identifier identifier);

  Stream<KeyEvent> streamKeyEvents(Identifier identifier, long from);

  Optional<KeyState> getKeyState(Identifier identifier);

  Optional<KeyState> getKeyState(KeyEventCoordinates previous);

  OptionalLong findLatestReceipt(Identifier forIdentifier, Identifier byIdentifier);
}
