package foundation.identity.keri.demo;

import foundation.identity.keri.QualifiedBase64;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.ReceiptFromBasicIdentifierEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferableIdentifierEvent;
import foundation.identity.keri.api.event.RotationEvent;

import java.util.List;
import java.util.function.Function;

import static java.util.Comparator.comparingInt;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;

public final class EventUtils {

  public static void printEvent(Event e) {
    System.out.printf("%s (KERI %s %s)\n", e.type(), e.version(), e.format());

    if (e instanceof IdentifierEvent) {
      var ie = (IdentifierEvent) e;
      System.out.println("i:  " + ie.identifier());
      System.out.println("s:  " + ie.sequenceNumber());
      System.out.println("p:  " + ie.previous().digest());

      if (e instanceof EstablishmentEvent) {
        var ee = (EstablishmentEvent) e;
        System.out.println("kt: " + ee.signingThreshold());
        System.out.println("k:  " + listToString(ee.keys(), QualifiedBase64::qb64));
        System.out.println("wt: " + ee.witnessThreshold());

        if (ee instanceof InceptionEvent) {
          var ic = (InceptionEvent) ee;
          System.out.println("w: " + listToString(ic.witnesses(), QualifiedBase64::qb64));
          System.out.println("c: " + ic.configurationTraits());
        }

        if (ee instanceof RotationEvent) {
          var re = (RotationEvent) ee;
          System.out.println("wr: " + listToString(re.removedWitnesses(), QualifiedBase64::qb64));
          System.out.println("wa: " + listToString(re.addedWitnesses(), QualifiedBase64::qb64));
          System.out.println("a:  " + listToString(re.seals(), Object::toString));
        }

        if (ee instanceof InteractionEvent) {
          var ix = (InteractionEvent) ee;
          System.out.println("a:  " + listToString(ix.seals(), Object::toString));
        }
      }

      System.out.println("--- SIGNATURES");
      ie.signatures().stream()
          .sorted(comparingInt(AttachedEventSignature::keyIndex))
          .forEachOrdered(es -> {
            System.out.print(es.keyIndex());
            System.out.println(": " + es.signature());
          });

    }

    if (e instanceof ReceiptFromBasicIdentifierEvent) {
      var r = (ReceiptFromBasicIdentifierEvent) e;
      var re = r.receipts().iterator().next();

      System.out.println("i: " + re.event().identifier());
      System.out.println("s: " + re.event().sequenceNumber());
      System.out.println("d: " + re.event().digest());

      System.out.println("--- SIGNATURES");
      r.receipts().stream()
          .sorted(comparingInt(es -> es.key().keyIndex()))
          .forEachOrdered(es -> {
            System.out.print(es.key().establishmentEvent().identifier());
            System.out.println(": " + es.signature());
          });
    }

    if (e instanceof ReceiptFromTransferableIdentifierEvent) {
      var vrc = (ReceiptFromTransferableIdentifierEvent) e;
      System.out.println("i: " + vrc.event().identifier());
      System.out.println("s: " + vrc.event().sequenceNumber());
      System.out.println("d: " + vrc.event().digest());

      System.out.println("--- SIGNATURES");
      vrc.signatures().stream()
          .sorted(comparingInt(AttachedEventSignature::keyIndex))
          .forEachOrdered(es -> {
            System.out.print(es.keyIndex());
            System.out.println(": " + es.signature());
          });
    }

    System.out.println("--- RAW");
    System.out.println(new String(e.bytes(), UTF_8));
  }

  private static <T> String listToString(List<T> list, Function<T, String> toString) {
    return list.stream()
        .map(toString)
        .collect(joining(",", "[", "]"));
  }

}
