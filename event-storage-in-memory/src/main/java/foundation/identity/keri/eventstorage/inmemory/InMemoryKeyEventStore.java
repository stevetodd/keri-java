package foundation.identity.keri.eventstorage.inmemory;

import foundation.identity.keri.KeyEventStore;
import foundation.identity.keri.KeyStateProcessor;
import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.SealingEvent;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.Digest;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.crypto.Signature;
import foundation.identity.keri.internal.event.ImmutableKeyEventCoordinates;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.stream.Stream;

import static java.util.Comparator.comparing;

public class InMemoryKeyEventStore implements KeyEventStore {

  private final ArrayList<KeyEvent> events = new ArrayList<>();
  private final Map<KeyEventCoordinates, KeyState> states = new HashMap<>();
  private final Map<KeyEventCoordinates, Map<Integer, Signature>> authentications = new HashMap<>();
  private final Map<KeyEventCoordinates, Map<Integer, Signature>> endorsements = new HashMap<>();
  private final Map<ReceiptKey, Map<Integer, Signature>> receipts = new HashMap<>();

  @Override
  public void append(KeyEvent event) {
    var previousState = this.getKeyState(event.previous()).orElse(null);
    var newState = KeyStateProcessor.apply(previousState, event);

    this.events.add(event);

    this.appendAttachments(
        event.coordinates(),
        event.authentication(),
        event.endorsements(),
        event.receipts());

    this.states.put(event.coordinates(), newState);
  }

  private void appendAttachments(
      KeyEventCoordinates event, Map<Integer,
      Signature> signatures,
      Map<Integer, Signature> receipts,
      Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts) {
    this.authentications.computeIfAbsent(event, k -> new HashMap<>())
        .putAll(signatures);

    this.endorsements.computeIfAbsent(event, k -> new HashMap<>())
        .putAll(receipts);

    for (var otherReceipt : otherReceipts.entrySet()) {
      var key = new ReceiptKey(event, otherReceipt.getKey());
      this.receipts.computeIfAbsent(key, k -> new HashMap<>())
          .putAll(otherReceipt.getValue());
    }
 }

  @Override
  public void append(AttachmentEvent event) {
    this.appendAttachments(event.coordinates(), event.authentication(), event.endorsements(), event.receipts());
  }

  @Override
  public Optional<SealingEvent> getKeyEvent(DelegatingEventCoordinates coordinates) {
    return this.events.stream()
        .filter(e -> e.identifier().equals(coordinates.identifier()))
        .filter(e -> e.sequenceNumber() == coordinates.sequenceNumber())
        .filter(e -> e.previous().digest().equals(coordinates.previousEvent().digest()))
        .filter(e -> e instanceof SealingEvent)
        .map(e -> (SealingEvent) e)
        .findFirst();
  }

  @Override
  public Optional<KeyEvent> getKeyEvent(KeyEventCoordinates coordinates) {
    return this.events.stream()
        .filter(e -> e.identifier().equals(coordinates.identifier()))
        .filter(e -> e.sequenceNumber() == coordinates.sequenceNumber())
        .filter(e ->
            Digest.equals(e.digest(), coordinates.digest())
              || DigestOperations.matches(e.bytes(), coordinates.digest()))
        .findFirst();
  }

  @Override
  public Stream<KeyEvent> streamKeyEvents(Identifier identifier) {
    return this.events.stream()
        .filter(e -> e.identifier().equals(identifier))
        .sorted(comparing(KeyEvent::sequenceNumber));
  }

  @Override
  public Stream<KeyEvent> streamKeyEvents(Identifier identifier, long from) {
    return this.streamKeyEvents(identifier)
        .dropWhile(e -> e.sequenceNumber() < from);
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
  public OptionalLong findLatestReceipt(
      Identifier forIdentifier, Identifier byIdentifier) {
    return this.receipts.keySet()
        .stream()
        .filter(receiptKey -> receiptKey.event().identifier().equals(forIdentifier))
        .filter(receiptKey -> receiptKey.signer().identifier().equals(byIdentifier))
        .mapToLong(receiptKey -> receiptKey.event().sequenceNumber())
        .max();
  }

  private static class ReceiptKey {
    private final KeyEventCoordinates event;
    private final KeyEventCoordinates signer;

    public ReceiptKey(KeyEventCoordinates event, KeyEventCoordinates signer) {
      this.event = ImmutableKeyEventCoordinates.convert(event);
      this.signer = ImmutableKeyEventCoordinates.convert(signer);
    }

    public KeyEventCoordinates event() {
      return this.event;
    }

    public KeyEventCoordinates signer() {
      return this.signer;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof ReceiptKey)) {
        return false;
      }
      ReceiptKey that = (ReceiptKey) o;
      return this.event.equals(that.event)
          && this.signer.equals(that.signer);
    }

    @Override
    public int hashCode() {
      return Objects.hash(this.event, this.signer);
    }
  }

}
