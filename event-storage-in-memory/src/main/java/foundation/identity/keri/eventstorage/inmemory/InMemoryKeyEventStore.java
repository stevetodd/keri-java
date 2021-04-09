package foundation.identity.keri.eventstorage.inmemory;

import foundation.identity.keri.KeyEventStore;
import foundation.identity.keri.KeyStateProcessor;
import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.ReceiptEvent;
import foundation.identity.keri.api.event.ReceiptFromBasicIdentifierEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferableIdentifierEvent;
import foundation.identity.keri.api.event.SealingEvent;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.internal.event.ImmutableEventSignature;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Comparator.comparing;

public class InMemoryKeyEventStore implements KeyEventStore {

  private final ArrayList<KeyEvent> events = new ArrayList<>();
  private final Map<KeyEventCoordinates, KeyState> states = new HashMap<>();
  private final Map<KeyEventCoordinates, Set<EventSignature>> signatures = new HashMap<>();

  @Override
  public void append(KeyEvent event) {
    var previousState = getKeyState(event.previous()).orElse(null);
    var newState = KeyStateProcessor.apply(previousState, event);

    var eventSignatures = event.signatures()
        .stream()
        .map(as -> ImmutableEventSignature.from(as, newState.lastEstablishmentEvent().coordinates()))
        .collect(Collectors.toSet());

    this.signatures.computeIfAbsent(
            event.coordinates(),
            k -> new HashSet<>())
        .addAll(eventSignatures);

    this.events.add(event);
    this.states.put(event.coordinates(), newState);
  }

  @Override
  public void append(ReceiptEvent event) {
    if (event instanceof ReceiptFromBasicIdentifierEvent) {
      var rct = (ReceiptFromBasicIdentifierEvent) event;
      this.signatures.computeIfAbsent(
          event.event(),
          k -> new HashSet<>())
          .addAll(rct.receipts());
    } else if (event instanceof ReceiptFromTransferableIdentifierEvent) {
      var vrc = (ReceiptFromTransferableIdentifierEvent) event;
      var eventSignatures = vrc.signatures().stream()
          .map(as -> ImmutableEventSignature.from(as, vrc.keyEstablishmentEvent()))
          .collect(Collectors.toSet());
      this.signatures.computeIfAbsent(
          event.event(),
          k -> new HashSet<>())
          .addAll(eventSignatures); // TODO find last establishment event for key mapping
    }
  }

  @Override
  public Optional<SealingEvent> getKeyEvent(DelegatingEventCoordinates coordinates) {
    return Optional.empty();
  }

  @Override
  public Optional<KeyEvent> getKeyEvent(KeyEventCoordinates coordinates) {
    return Optional.empty();
  }

  @Override
  public Stream<KeyEvent> streamKeyEvents(Identifier identifier) {
    return this.events.stream()
        .filter(e -> e.identifier().equals(identifier))
        .sorted(comparing(KeyEvent::sequenceNumber));
  }

  @Override
  public Stream<KeyEvent> streamKeyEvents(Identifier identifier, BigInteger from) {
    return streamKeyEvents(identifier)
        .dropWhile(e -> e.sequenceNumber().compareTo(from) < 0);
  }

  @Override
  public Optional<KeyState> getKeyState(Identifier identifier) {
    // FIXME doesn't take duplicity into account
    return this.states.values().stream()
        .filter(s -> s.identifier().equals(identifier))
        .max(comparing(s -> s.lastEvent().sequenceNumber()));
  }

  @Override
  public Optional<KeyState> getKeyState(KeyEventCoordinates coordinates) {
    return Optional.ofNullable(this.states.get(coordinates));
  }

  @Override
  public Optional<EventSignature> findLatestReceipt(
      Identifier forIdentifier, Identifier byIdentifier) {
    // FIXME doesn't handle duplicity, though the only use so far is for
    //       figuring out what the other side lacks
    return this.signatures.entrySet()
        .stream()
        .filter(kv -> kv.getKey().identifier().equals(forIdentifier))
        .flatMap(kv -> kv.getValue().stream())
        .filter(es -> es.key().establishmentEvent().identifier().equals(byIdentifier))
        .max(comparing(es -> es.event().sequenceNumber()));
  }

}
