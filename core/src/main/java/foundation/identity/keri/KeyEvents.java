package foundation.identity.keri;

import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.DelegatedEstablishmentEvent;
import foundation.identity.keri.api.event.DelegatedInceptionEvent;
import foundation.identity.keri.api.event.DelegatedRotationEvent;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.RotationEvent;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;

public final class KeyEvents {

  public static String toString(KeyEvent e) {
    var sb = new StringBuilder();
    sb.append(format("%s (KERI %s %s)", type(e.getClass()), e.version(), e.format())).append("\n");
    sb.append("i:  ").append(e.identifier()).append("\n");
    sb.append("s:  ").append(e.sequenceNumber()).append("\n");
    sb.append("p:  ").append(e.previous().digest()).append("\n");

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

      if (ee instanceof DelegatedEstablishmentEvent) {
        var dee = (DelegatedEstablishmentEvent) ee;
        sb.append("da:  ").append(dee.delegatingEvent()).append("\n");
      }

    }

    if (e instanceof InteractionEvent) {
      var ix = (InteractionEvent) e;
      sb.append("a:  ").append(listToString(ix.seals(), Object::toString)).append("\n");
    }

    if (e instanceof AttachmentEvent) {
      var add = (AttachmentEvent) e;
      sb.append("d: ").append(add.coordinates().digest()).append("\n");
    }

    sb.append("--- CONTROLLER SIGNATURES").append("\n");
    e.signatures()
        .entrySet()
        .stream()
        .sorted(Map.Entry.comparingByKey())
        .forEachOrdered(kv -> {
          sb.append(kv.getKey());
          sb.append(":");
          sb.append(kv.getValue());
          sb.append("\n");
        });

    sb.append("--- WITNESS RECEIPTS").append("\n");
    e.receipts()
        .entrySet()
        .stream()
        .sorted(Map.Entry.comparingByKey())
        .forEachOrdered(kv -> {
          sb.append(kv.getKey());
          sb.append(":");
          sb.append(kv.getValue());
          sb.append("\n");
        });

    sb.append("--- OTHER RECEIPTS").append("\n");
    e.otherReceipts()
        .entrySet()
        .stream()
        .map(kv -> Map.entry(kv.getKey().toString(), kv.getValue()))
        .sorted(Map.Entry.comparingByKey())
        .forEachOrdered(kv -> {
          sb.append(kv.getKey());
          sb.append(":");
          sb.append(kv.getValue());
          sb.append("\n");
        });

    sb.append("--- RAW").append("\n");
    sb.append(new String(e.bytes(), UTF_8));

    return sb.toString();
  }

  private static String type(Class<? extends KeyEvent> cls) {
    // JDK17: use switch + sealed classes
    if (DelegatedInceptionEvent.class.isAssignableFrom(cls)) {
      return "dip";
    } else if (DelegatedRotationEvent.class.isAssignableFrom(cls)) {
      return "drt";
    } else if (InceptionEvent.class.isAssignableFrom(cls)) {
      return "icp";
    } else if (RotationEvent.class.isAssignableFrom(cls)) {
      return "rot";
    } else if (InteractionEvent.class.isAssignableFrom(cls)) {
      return "ixn";
//    } else if (ReceiptFromBasicIdentifierEvent.class.isAssignableFrom(cls)) {
//      return "rct";
//    } else if (ReceiptFromTransferableIdentifierEvent.class.isAssignableFrom(cls)) {
//      return "vrc";
    } else {
      return "???" + cls.getSimpleName();
    }
  }

  private static <T> String listToString(List<T> list, Function<T, String> toString) {
    return list.stream()
        .map(toString)
        .collect(joining(",", "[", "]"));
  }

  public static String shortCoordinates(KeyEventCoordinates coordinates) {
    return ShortQualifiedBase64.shortQb64(coordinates.identifier()) + ":"
        + coordinates.sequenceNumber() + ":"
        + ShortQualifiedBase64.shortQb64(coordinates.digest());
  }

}
