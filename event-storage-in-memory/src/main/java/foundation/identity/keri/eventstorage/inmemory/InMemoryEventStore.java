package foundation.identity.keri.eventstorage.inmemory;

import foundation.identity.keri.EventStore;
import foundation.identity.keri.QualifiedBase64;
import foundation.identity.keri.ShortQualifiedBase64;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.EventType;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static foundation.identity.keri.ShortQualifiedBase64.shortQb64;
import static java.util.Comparator.comparing;
import static java.util.Comparator.comparingInt;
import static java.util.Map.Entry.comparingByKey;
import static java.util.stream.Collectors.groupingBy;

/**
 * For testing using only. No attempts have been made to make this performant.
 */
public class InMemoryEventStore implements EventStore {

  private static final Comparator<IdentifierEvent> eventsBySequenceNumber = comparing(IdentifierEvent::sequenceNumber);
  private static final Comparator<IdentifierEvent> eventsByIdentifier = comparing((IdentifierEvent e) -> QualifiedBase64
      .qb64(e.identifier()));

  private final ArrayList<IdentifierEvent> events = new ArrayList<>();
  private final ArrayList<AttachedEventSignature> signatures = new ArrayList<>();
  private final ArrayList<EventSignature> receipts = new ArrayList<>();

  @Override
  public void store(IdentifierEvent event) {
    this.events.add(event);
    this.signatures.addAll(event.signatures());
  }

  @Override
  public Stream<IdentifierEvent> find(Identifier identifier) {
    return this.events.stream()
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
    System.out.println("\n*** findLatestReceipt for:" + forIdentifier + " by:" + byIdentifier);
    printContents();
    return this.receipts.stream()
        .filter(es -> es.event().identifier().equals(forIdentifier))
        .filter(es -> es.key().establishmentEvent().identifier().equals(byIdentifier))
        .max(comparing(es -> es.event().sequenceNumber()));
  }

  @Override
  public void store(AttachedEventSignature signature) {
    this.signatures.add(signature);
  }

  @Override
  public void store(EventSignature eventSignature) {
    this.receipts.add(eventSignature);
  }

  public void printContents() {
    System.out.println("= EVENT STORE ====================================================");
    System.out.println();
    System.out.println("EVENTS:"); // TODO improve
    System.out.println("--------------------------------------------------------------------");
    this.events.stream()
        .sorted(eventsByIdentifier.thenComparing(eventsBySequenceNumber))
        .collect(groupingBy(IdentifierEvent::identifier))
        .entrySet()
        .stream()
        .sorted(comparingByKey(comparing(Identifier::toString)))
        .forEachOrdered(kv -> {
          System.out.println(kv.getKey() + ":");
          kv.getValue()
              .stream()
              .sorted(comparing(IdentifierEvent::sequenceNumber)
                  .thenComparing(e -> e.previous().toString()))
              .forEachOrdered(e -> System.out.println("  " + e.sequenceNumber() + " -> " + event(e)));
        });
        //.forEachOrdered(e -> System.out.println(new String(e.bytes())));

    System.out.println();
    System.out.println("SIGNATURES (identifier, sequenceNumber:digest, keyIndex:signature):");
    System.out.println("--------------------------------------------------------------------");
    this.signatures.stream()
        .collect(
            groupingBy(as -> as.event().identifier(),
                groupingBy(as -> as.event().sequenceNumber() + ":" + shortQb64(as.event().digest()))))
        .entrySet()
        .stream()
        .sorted(comparingByKey(comparing(Object::toString)))
        .forEachOrdered(kv -> {
          System.out.println(kv.getKey() + ":");
          kv.getValue()
              .entrySet()
              .stream()
              .sorted(comparingByKey())
              .forEachOrdered(kv1 -> {
                System.out.println("  " + kv1.getKey() + ":");
                kv1.getValue().stream()
                    .sorted(comparingInt(AttachedEventSignature::keyIndex))
                    .forEachOrdered(as -> System.out.println("    " + as.keyIndex() + ": " + shortQb64(as.signature())));

              });
        });

    System.out.println();
    System.out.println("RECEIPTS (identifier, sequenceNumber:digest, signer:signature):");
    System.out.println("------------------------------------------------------------------");
    this.receipts.stream()
        .collect(
            groupingBy(es -> shortQb64(es.event().identifier()),
                groupingBy(es -> es.event().sequenceNumber() + ":" + shortQb64(es.event().digest()))))
        .entrySet()
        .stream()
        .sorted(comparingByKey())
        .forEachOrdered(kv -> {
          System.out.println(kv.getKey() + ":");
          kv.getValue().entrySet().stream()
              .sorted(comparingByKey())
              .forEachOrdered(kv1 -> {
                System.out.println("  " + kv1.getKey() + ":");
                kv1.getValue().stream()
                    .sorted(comparing(es -> es.key().establishmentEvent().identifier().toString()))
                    .forEachOrdered(es -> System.out.println("    " + shortQb64(es.key().establishmentEvent().identifier()) + ": " + shortQb64(es.signature())));
              });
        });

    System.out.println("==================================================================");
    System.out.println();
  }

  private static String event(Event e) {
    var sb = new StringBuilder();
    sb.append("t=");
    sb.append(type(e.type()));

    if (e instanceof IdentifierEvent) {
      var ie = (IdentifierEvent) e;
      if (!IdentifierEventCoordinatesWithDigest.NONE.equals(ie.previous())) {
        sb.append(" p=").append(shortQb64(ie.previous().digest()));
      }

      if (e instanceof EstablishmentEvent) {
        var ee = (EstablishmentEvent) e;
        sb.append(" kt=");
        sb.append(ee.signingThreshold());

        sb.append(" k=");
        sb.append(listToString(ee.keys(), ShortQualifiedBase64::shortQb64));

        sb.append(" wt=");
        sb.append(ee.witnessThreshold());

        if (ee instanceof InceptionEvent) {
          var ic = (InceptionEvent) ee;
          sb.append(" w=");
          sb.append(listToString(ic.witnesses(), ShortQualifiedBase64::shortQb64));
          sb.append(" c=");
          sb.append(ic.configurationTraits());
        }

        if (ee instanceof RotationEvent) {
          var re = (RotationEvent) ee;
          sb.append(" wr=");
          sb.append(listToString(re.removedWitnesses(), ShortQualifiedBase64::shortQb64));
          sb.append(" wa=");
          sb.append(listToString(re.addedWitnesses(), ShortQualifiedBase64::shortQb64));
          sb.append(" a=");
          sb.append(listToString(re.seals(), Object::toString));
        }

        if (ee instanceof InteractionEvent) {
          var ix = (InteractionEvent) ee;
          sb.append(" a=");
          sb.append(listToString(ix.seals(), Object::toString));
        }
      }
    }

    return sb.toString();
  }

  private static String type(EventType t) {
    return switch (t) {
      case INCEPTION -> "icp";
      case ROTATION -> "rot";
      case INTERACTION -> "ixn";
      case DELEGATED_INCEPTION -> "dip";
      case DELEGATED_ROTATION -> "drt";
      default -> t.toString();
    };
  }

  private static <T> String listToString(List<T> list, Function<T, String> toString) {
    return list.stream().map(toString).collect(Collectors.joining(",", "[", "]"));
  }

}
