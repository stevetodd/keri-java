package foundation.identity.keri.eventstorage.inmemory;

import foundation.identity.keri.EventStore;
import foundation.identity.keri.QualifiedBase64;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Comparator.comparing;

public class InMemoryEventStore implements EventStore {

  private static final Comparator<IdentifierEvent> eventsBySequenceNumber = comparing(IdentifierEvent::sequenceNumber);
  private static final Comparator<IdentifierEvent> eventsByIdentifier = comparing((IdentifierEvent e) -> QualifiedBase64
      .qb64(e.identifier()));

  private final ArrayList<IdentifierEvent> events = new ArrayList<>();
  private final ArrayList<EventSignature> signatures = new ArrayList<>();


  @Override
  public void store(IdentifierEvent event) {
    this.events.add(event);
    this.signatures.addAll(event.signatures());
  }

  @Override
  public Stream<IdentifierEvent> find(Identifier identifier) {
    return events.stream()
        .filter(e -> e.identifier().equals(identifier))
        .sorted(eventsBySequenceNumber);
  }


  @Override
  public Stream<IdentifierEvent> find(Identifier identifier, BigInteger fromInclusive) {
    return find(identifier)
        .filter(e -> e.sequenceNumber().compareTo(fromInclusive) >= 0);
  }

  @Override
  public Optional<EventSignature> findLatestReceipt(
      Identifier forIdentifier, Identifier byIdentifier) {
    return this.signatures.stream()
        .filter(es -> es.event().identifier().equals(forIdentifier))
        .filter(es -> es.key().identifier().equals(byIdentifier))
        .max(comparing(es -> es.event().sequenceNumber()));
  }

  @Override
  public void store(EventSignature eventSignature) {
    this.signatures.add(eventSignature);
  }

  public void printContents() {
    System.out.println();
    System.out.println("====== EVENT STORE ======");
    System.out.println("EVENTS:");
    events.stream()
        .sorted(eventsByIdentifier.thenComparing(eventsBySequenceNumber))
        .forEachOrdered(e -> System.out.println(new String(e.bytes())));

    System.out.println("SIGNATURES:");
    signatures.stream()
        .sorted(
            comparing((EventSignature s) -> QualifiedBase64.qb64(s.event().identifier()))
                .thenComparing((EventSignature s) -> s.event().sequenceNumber())
                .thenComparing((EventSignature s) -> QualifiedBase64.qb64(s.event().digest()))
                .thenComparingInt((EventSignature s) -> s.key().index()))
        .forEachOrdered(System.out::println);

    System.out.println("=========================");
    System.out.println();
  }

}
