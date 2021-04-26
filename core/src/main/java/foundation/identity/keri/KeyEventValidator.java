package foundation.identity.keri;

import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.event.DelegatedEstablishmentEvent;
import foundation.identity.keri.api.event.DelegatedRotationEvent;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;
import foundation.identity.keri.api.identifier.SelfSigningIdentifier;
import foundation.identity.keri.api.seal.KeyEventCoordinatesSeal;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.crypto.SignatureOperations;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static foundation.identity.keri.api.event.ConfigurationTrait.ESTABLISHMENT_EVENTS_ONLY;
import static java.util.Collections.disjoint;

public class KeyEventValidator {

  private final KeyEventStore eventStore;

  public KeyEventValidator(KeyEventStore eventStore) {
    this.eventStore = eventStore;
  }

  public void validate(KeyState state, KeyEvent event) {
    /*if (event instanceof AttachmentEvent) {
      validate((AttachmentEvent) event);
    } else*/ if (event instanceof KeyEvent) {
      this.validateKeyEvent(state, event);
    } else {
      throw new IllegalArgumentException("Unknown event type: " + event.getClass().getCanonicalName());
    }
  }

  private void validateKeyEvent(KeyState state, KeyEvent event) {
    //validateAttachedSignatures(event, state);

    if (event instanceof EstablishmentEvent) {
      var ee = (EstablishmentEvent) event;

      this.validateKeyConfiguration(ee);

      this.validate(ee.identifier().transferable() || ee.nextKeyConfiguration().isEmpty(),
          "non-transferable prefix must not have a next key configuration");

      if (event instanceof InceptionEvent) {
        var icp = (InceptionEvent) ee;

        this.validate(icp.sequenceNumber() == 0,
            "inception events must have a sequence number of 0");

        this.validateIdentifier(icp);

        this.validateInceptionWitnesses(icp);
      } else if (event instanceof RotationEvent) {
        var rot = (RotationEvent) ee;

        this.validate(!(state.delegated()) || rot instanceof DelegatedRotationEvent,
            "delegated identifiers must use delegated rotation event type");

        this.validate(rot.sequenceNumber() > 0,
            "non-inception event must have a sequence number greater than 0 (s: %s)",
            rot.sequenceNumber());

        this.validate(event.identifier().transferable(),
            "only transferable identifiers can have rotation events");

        this.validate(state.lastEstablishmentEvent().nextKeyConfiguration().isPresent(),
            "previous establishment event must have a next key configuration for rotation");

        var nextKeyConfigurationDigest = state.lastEstablishmentEvent().nextKeyConfiguration().get();
        this.validate(KeyConfigurationDigester.matches(rot.signingThreshold(), rot.keys(), nextKeyConfigurationDigest),
            "digest of signing threshold and keys must match digest in previous establishment event");

        this.validateRotationWitnesses(rot, state);
      }

      if (event instanceof DelegatedEstablishmentEvent) {
        var dee = (DelegatedEstablishmentEvent) ee;
        var delegatingEvent = this.eventStore.getKeyEvent(dee.delegatingEvent())
            .orElseThrow(() -> new OutOfOrderException(event, dee.delegatingEvent()));

        this.validate(this.containsSeal(delegatingEvent.seals(), dee),
            "delegated establishment event seal must contain be contained in referenced delegating event");
      }
    } else if (event instanceof InteractionEvent) {
      var ixn = (InteractionEvent) event;

      this.validate(ixn.sequenceNumber() > 0,
          "non-inception event must have a sequence number greater than 0 (s: %s)",
          ixn.sequenceNumber());

      this.validate(!state.configurationTraits().contains(ESTABLISHMENT_EVENTS_ONLY),
          "interaction events only permitted when identifier is not configured for establishment events only");
    }
  }

  private boolean containsSeal(List<Seal> seals, DelegatedEstablishmentEvent event) {
    for (var s : seals) {
      if (s instanceof KeyEventCoordinatesSeal) {
        var ecds = (KeyEventCoordinatesSeal) s;
        if (ecds.event().identifier().equals(event.identifier())
            && ecds.event().sequenceNumber() == event.sequenceNumber()
            && DigestOperations.matches(event.bytes(), ecds.event().digest())) {
          return true;
        }
      }
    }
    return false;
  }

  private void validateRotationWitnesses(RotationEvent rot, KeyState state) {
    this.validate(distinct(rot.removedWitnesses()),
        "removed witnesses must not have duplicates");

    this.validate(distinct(rot.removedWitnesses()),
        "added witnesses must not have duplicates");

    this.validate(state.witnesses().containsAll(rot.removedWitnesses()),
        "removed witnesses must be present witness list");

    this.validate(disjoint(rot.addedWitnesses(), rot.removedWitnesses()),
        "added and removed witnesses must be mutually exclusive");

    this.validate(disjoint(rot.addedWitnesses(), state.witnesses()),
        "added witnesses must not already be present in witness list");

    var newWitnesses = new ArrayList<>(state.witnesses());
    newWitnesses.removeAll(rot.removedWitnesses());
    newWitnesses.addAll(rot.addedWitnesses());

    this.validate(rot.witnessThreshold() >= 0,
        "witness threshold must not be negative");

    if (newWitnesses.isEmpty()) {
      this.validate(rot.witnessThreshold() == 0,
          "witness threshold must be 0 if no witnesses are specified");
    } else {
      this.validate(rot.witnessThreshold() <= newWitnesses.size(),
          "witness threshold must be less than or equal to the number of witnesses " +
              "(threshold: %s, witnesses: %s)",
          rot.witnessThreshold(), newWitnesses.size());
    }
  }

  private static <T> boolean distinct(Collection<T> items) {
    if (items instanceof Set) {
      return true;
    }

    var set = new HashSet<T>();
    for (var i : items) {
      if (!set.add(i)) {
        return false;
      }
    }

    return true;
  }

  private void validateInceptionWitnesses(InceptionEvent icp) {
    if (icp.witnesses().isEmpty()) {
      this.validate(icp.witnessThreshold() == 0,
          "witness threshold must be 0 if no witnesses are provided");
    } else {
      this.validate(distinct(icp.witnesses()),
          "witness set must not have duplicates");

      this.validate(icp.witnessThreshold() > 0,
          "witness threshold must be greater than 0 if witnesses are provided (given: threshold: %s, witnesses: %s",
          icp.witnessThreshold(), icp.witnesses().size());

      this.validate(icp.witnessThreshold() <= icp.witnesses().size(),
          "witness threshold must be less than or equal to the number of witnesses (given: threshold: %s, witnesses: %s",
          icp.witnessThreshold(), icp.witnesses().size());
    }
  }

  private void validateIdentifier(InceptionEvent event) {
    if (event.identifier() instanceof BasicIdentifier) {

      this.validate(event.keys().size() == 1,
          "basic prefixes can only have a single key");

      this.validate(((BasicIdentifier) event.identifier()).publicKey().equals(event.keys().get(0)),
          "basic prefix key must match event key");

    } else if (event.identifier() instanceof SelfAddressingIdentifier) {
      var sap = (SelfAddressingIdentifier) event.identifier();
      var ops = DigestOperations.lookup(sap.digest().algorithm());
      var digest = ops.digest(event.inceptionStatement());

      this.validate(Digest.equals(sap.digest(), digest),
          "self-addressing prefix digest must match digest of inception event");

    } else if (event.identifier() instanceof SelfSigningIdentifier) {
      var ssp = (SelfSigningIdentifier) event.identifier();

      this.validate(event.keys().size() == 1,
          "self-signing prefixes can only have a single key");

      var ops = SignatureOperations.lookup(event.keys().get(0));
      this.validate(ops.verify(event.inceptionStatement(), ssp.signature(), event.keys().get(0)),
          "self-signing prefix signature must verify against inception statement");

    } else {
      throw new IllegalArgumentException("Unknown prefix type: " + event.identifier().getClass());
    }
  }

  private void validateKeyConfiguration(EstablishmentEvent ee) {
    this.validate(!ee.keys().isEmpty(),
        "establishment events must have at least one key");

    if (ee.signingThreshold() instanceof SigningThreshold.Unweighted) {
      this.validate(ee.keys().size() >= ((SigningThreshold.Unweighted) ee.signingThreshold()).threshold(),
          "unweighted signing threshold must be less than or equals to the number of keys");
    } else if (ee.signingThreshold() instanceof SigningThreshold.Weighted) {
      var weightedThreshold = ((SigningThreshold.Weighted) ee.signingThreshold());
      var countOfWeights = SigningThresholds.countWeights(weightedThreshold.weights());
      this.validate(ee.keys().size() == countOfWeights,
          "weighted signing threshold must specify a weight for each key");
    }
  }

  /*public void validateAttachedSignatures(KeyEvent event, KeyState state) {
    var keyEstablishmentEvent = event instanceof EstablishmentEvent
        ? (EstablishmentEvent) event
        : state.lastEstablishmentEvent();
    var indexes = new ArrayList<Integer>();

    for (var as : event.signatures()) {
      validate(as.keyIndex() < keyEstablishmentEvent.keys().size(),
          "signature index must reference a key in the current establishment event " +
              "(signature-index: %s, key-list-size: %s)",
          as.keyIndex(), keyEstablishmentEvent.keys().size());

      var key = keyEstablishmentEvent.keys().get(as.keyIndex());
      var ops = SignatureOperations.lookup(key);

      if (ops.verify(event.bytes(), as.signature(), key)) {
        indexes.add(as.keyIndex());
      }
    }

    var indexArray = indexes.stream().mapToInt(Integer::intValue).toArray();

    if (!thresholdMet(keyEstablishmentEvent.signingThreshold(), indexArray)) {
      throw new UnmetSigningThresholdException();
    }
  }

  private void validate(AttachmentEvent addendum) {
    // TODO figure out algo agility--who is responsible to try different algos?
    // TODO latest event at i,s instead of i,s,d?
    var event = this.eventStore.getKeyEvent(addendum.coordinates())
        .orElseThrow(() -> new OutOfOrderException(addendum, addendum.coordinates()));

    // TODO generalize

    if (addendum instanceof ReceiptFromBasicIdentifierEvent) {
      var rct = (ReceiptFromBasicIdentifierEvent) addendum;

      for (var es : rct.receipts()) {
        if (!(es.key().establishmentEvent().identifier() instanceof BasicIdentifier)) {
          // keripy just skips it, so I guess we will to
          continue;
        }
        var id = (BasicIdentifier) es.key().establishmentEvent().identifier();
        var ops = SignatureOperations.lookup(id.publicKey());

        validate(ops.verify(event.bytes(), es.signature(), id.publicKey()),
            "signature must verify against referenced event");
      }
    } else if (addendum instanceof ReceiptFromTransferableIdentifierEvent) {
      var vrc = (ReceiptFromTransferableIdentifierEvent) addendum;
      // TODO figure out algo agility--who is responsible to try different algos?
      // TODO latest event at i,s instead of i,s,d?
      var keyEvent = this.eventStore.getKeyEvent(vrc.keyEstablishmentEvent())
          .orElseThrow(() -> new OutOfOrderException(addendum, vrc.keyEstablishmentEvent()));

      validate(keyEvent instanceof EstablishmentEvent,
          "seal must reference an establishment event");

      var ee = (EstablishmentEvent) keyEvent;
      for (var as : vrc.signatures()) {
        var es = ImmutableEventSignature.from(as, vrc.keyEstablishmentEvent());

        validate(es.key().keyIndex() < ee.keys().size(),
            "signature key index must reference a listed key");

        var key = ee.keys().get(es.key().keyIndex());
        var ops = SignatureOperations.lookup(key);

        validate(ops.verify(event.bytes(), es.signature(), key),
            "signatures must verify against referenced event");
      }

    }
  }*/

  private void validate(boolean valid, String message, Object... formatValues) {
    if (!valid) {
      throw new InvalidKeyEventException(String.format(message, formatValues));
    }
  }

}
