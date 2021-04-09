package foundation.identity.keri;

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

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Comparator.comparingInt;
import static java.util.stream.Collectors.joining;

public final class KeyEvents {

  public static String toString(Event e) {
    var sb = new StringBuilder();
    sb.append(format("%s (KERI %s %s)", e.type(), e.version(), e.format())).append("\n");

    if (e instanceof IdentifierEvent) {
      var ie = (IdentifierEvent) e;
      sb.append("i:  ").append(ie.identifier()).append("\n");
      sb.append("s:  ").append(ie.sequenceNumber()).append("\n");
      sb.append("p:  ").append(ie.previous().digest()).append("\n");

      if (e instanceof EstablishmentEvent) {
        var ee = (EstablishmentEvent) e;
        sb.append("kt: ").append(ee.signingThreshold()).append("\n");
        sb.append("k:  ").append(listToString(ee.keys(), QualifiedBase64::qb64)).append("\n");
        sb.append("wt: ").append(ee.witnessThreshold()).append("\n");

        if (ee instanceof InceptionEvent) {
          var ic = (InceptionEvent) ee;
          sb.append("w: ").append(listToString(ic.witnesses(), QualifiedBase64::qb64)).append("\n");
          sb.append("c: ").append(ic.configurationTraits()).append("\n");
        }

        if (ee instanceof RotationEvent) {
          var re = (RotationEvent) ee;
          sb.append("wr: ").append(listToString(re.removedWitnesses(), QualifiedBase64::qb64)).append("\n");
          sb.append("wa: ").append(listToString(re.addedWitnesses(), QualifiedBase64::qb64)).append("\n");
          sb.append("a:  ").append(listToString(re.seals(), Object::toString)).append("\n");
        }

        if (ee instanceof InteractionEvent) {
          var ix = (InteractionEvent) ee;
          sb.append("a:  ").append(listToString(ix.seals(), Object::toString)).append("\n");
        }
      }

      sb.append("--- SIGNATURES").append("\n");
      ie.signatures().stream()
          .sorted(comparingInt(AttachedEventSignature::keyIndex))
          .forEachOrdered(es -> {
            sb.append(es.keyIndex());
            sb.append(": ").append(es.signature()).append("\n");
          });

    }

    if (e instanceof ReceiptFromBasicIdentifierEvent) {
      var r = (ReceiptFromBasicIdentifierEvent) e;
      var re = r.receipts().iterator().next();

      sb.append("i: ").append(re.event().identifier()).append("\n");
      sb.append("s: ").append(re.event().sequenceNumber()).append("\n");
      sb.append("d: ").append(re.event().digest()).append("\n");

      sb.append("--- SIGNATURES");
      r.receipts().stream()
          .sorted(comparingInt(es -> es.key().keyIndex()))
          .forEachOrdered(es -> {
            sb.append(es.key().establishmentEvent().identifier());
            sb.append(": ").append(es.signature()).append("\n");
          });
    }

    if (e instanceof ReceiptFromTransferableIdentifierEvent) {
      var vrc = (ReceiptFromTransferableIdentifierEvent) e;
      sb.append("i: ").append(vrc.event().identifier()).append("\n");
      sb.append("s: ").append(vrc.event().sequenceNumber()).append("\n");
      sb.append("d: ").append(vrc.event().digest()).append("\n");

      sb.append("--- CONTROLLER SIGNATURES");
      vrc.signatures().stream()
          .sorted(comparingInt(AttachedEventSignature::keyIndex))
          .forEachOrdered(es -> {
            sb.append(es.keyIndex());
            sb.append(": ").append(es.signature()).append("\n");
          });
    }

    sb.append("--- RAW").append("\n");
    sb.append(new String(e.bytes(), UTF_8)).append("\n");
    return sb.toString();
  }

  private static <T> String listToString(List<T> list, Function<T, String> toString) {
    return list.stream()
        .map(toString)
        .collect(joining(",", "[", "]"));
  }

}
