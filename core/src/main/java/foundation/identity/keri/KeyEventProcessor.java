package foundation.identity.keri;

import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.DelegatedEstablishmentEvent;
import foundation.identity.keri.api.event.DelegatedRotationEvent;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;
import foundation.identity.keri.api.identifier.SelfSigningIdentifier;
import foundation.identity.keri.api.seal.KeyEventCoordinatesSeal;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.crypto.SignatureOperations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static foundation.identity.keri.api.event.ConfigurationTrait.ESTABLISHMENT_EVENTS_ONLY;
import static java.util.Collections.disjoint;

public final class KeyEventProcessor {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeyEventProcessor.class);

  final KeyEventStore keyEventStore;

  public KeyEventProcessor(KeyEventStore keyEventStore) {
    this.keyEventStore = keyEventStore;
  }

  public KeyEventStore keyEventStore() {
    return this.keyEventStore;
  }

  public void process(KeyEvent event) throws KeyEventProcessingException {
    KeyState previousState = null;

    if (!(event instanceof InceptionEvent)) {
      previousState = this.keyEventStore.getKeyState(event.previous())
          .orElseThrow(() -> new MissingEventException(event, event.previous()));
    }

    this.validateKeyEventData(previousState, event);

    var newState = KeyStateProcessor.apply(previousState, event);

    var validControllerSignatures = this.verifyControllerSignatures(newState, event, event.signatures());
    var validWitnessReceipts = this.verifyWitnessReceipts(newState, event, event.receipts());
    var validOtherReceipts = this.verifyOtherReceipts(event, event.otherReceipts());

    // TODO remove invalid signatures before appending
    this.keyEventStore.append(event);
  }

  public void process(AttachmentEvent attachmentEvent) throws AttachmentEventProcessingException {
    var event = this.keyEventStore.getKeyEvent(attachmentEvent.coordinates())
        .orElseThrow(() -> new MissingReferencedEventException(attachmentEvent, attachmentEvent.coordinates()));
    var state = this.keyEventStore.getKeyState(attachmentEvent.coordinates())
        .orElseThrow(() -> new MissingReferencedEventException(attachmentEvent, attachmentEvent.coordinates()));

    var validControllerSignatures = this.verifyControllerSignatures(state, event, event.signatures());
    var validWitnessReceipts = this.verifyWitnessReceipts(state, event, event.receipts());
    var validOtherReceipts = this.verifyOtherReceipts(event, event.otherReceipts());

    this.keyEventStore.append(attachmentEvent);
  }

  private HashMap<Integer, Signature> verifyControllerSignatures(KeyState state, KeyEvent event, Map<Integer, Signature> signatures) {
    var kee = state.lastEstablishmentEvent();

    var verifiedSignatures = new HashMap<Integer, Signature>();
    for (var kv : signatures.entrySet()) {
      var keyIndex = kv.getKey();

      if (keyIndex < 0 || keyIndex >= kee.keys().size()) {
        LOGGER.debug("signature keyIndex out of range: {}", keyIndex);
        continue;
      }

      var publicKey = kee.keys().get(kv.getKey());
      var signature = kv.getValue();

      var ops = SignatureOperations.lookup(publicKey);
      if (ops.verify(event.bytes(), signature, publicKey)) {
        verifiedSignatures.put(keyIndex, signature);
      } else {
        LOGGER.debug("signature invalid: {}", keyIndex);
      }
    }

    var arrIndexes = verifiedSignatures.keySet()
        .stream()
        .mapToInt(Integer::intValue)
        .toArray();
    if (!SigningThresholds.thresholdMet(kee.signingThreshold(), arrIndexes)) {
      throw new UnmetSigningThresholdException(event);
    }

    return verifiedSignatures;
  }

  private Map<Integer, Signature> verifyWitnessReceipts(KeyState state, KeyEvent event, Map<Integer, Signature> receipts) {
    var validReceipts = new HashMap<Integer, Signature>();
    for (var kv : receipts.entrySet()) {
      var witnessIndex = kv.getKey();

      if (witnessIndex < 0 || witnessIndex >= state.witnesses().size()) {
        LOGGER.debug("witness index out of range: {}", witnessIndex);
        continue;
      }

      var publicKey = state.witnesses().get(witnessIndex).publicKey();
      var signature = kv.getValue();

      var ops = SignatureOperations.lookup(publicKey);
      if (ops.verify(event.bytes(), signature, publicKey)) {
        validReceipts.put(witnessIndex, signature);
      } else {
        LOGGER.debug("invalid receipt from witness {}", witnessIndex);
      }
    }

    if (validReceipts.size() < state.witnessThreshold()) {
      throw new UnmetWitnessThresholdException(event);
    }

    return validReceipts;
  }

  private Map<KeyEventCoordinates, Map<Integer, Signature>> verifyOtherReceipts(KeyEvent event, Map<KeyEventCoordinates,
      Map<Integer, Signature>> otherReceipts) {
    var verified = new HashMap<KeyEventCoordinates, Map<Integer, Signature>>();
    for (var kv : otherReceipts.entrySet()) {
      // TODO escrow or something
      var keyState = this.keyEventStore.getKeyState(kv.getKey());

      if (keyState.isEmpty()) {
        continue;
      }

      var verifiedSignatures = this.verifyControllerSignatures(keyState.get(), event, kv.getValue());
      verified.put(kv.getKey(), verifiedSignatures);
    }

    return verified;
  }

  private void validateKeyEventData(KeyState state, KeyEvent event) {
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
        var delegatingEvent = this.keyEventStore.getKeyEvent(dee.delegatingEvent())
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

  private void validateIdentifier(InceptionEvent event) {
    if (event.identifier() instanceof BasicIdentifier) {

      this.validate(event.keys().size() == 1,
          "basic identifiers can only have a single key");

      this.validate(((BasicIdentifier) event.identifier()).publicKey().equals(event.keys().get(0)),
          "basic identifier key must match event key");

    } else if (event.identifier() instanceof SelfAddressingIdentifier) {
      var sap = (SelfAddressingIdentifier) event.identifier();
      var ops = DigestOperations.lookup(sap.digest().algorithm());
      var digest = ops.digest(event.inceptionStatement());

      this.validate(Digest.equals(sap.digest(), digest),
          "self-addressing identifier digests must match digest of inception statement");

    } else if (event.identifier() instanceof SelfSigningIdentifier) {
      var ssp = (SelfSigningIdentifier) event.identifier();

      this.validate(event.keys().size() == 1,
          "self-signing identifiers can only have a single key");

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

  private void validate(boolean valid, String message, Object... formatValues) {
    if (!valid) {
      throw new InvalidKeyEventException(String.format(message, formatValues));
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

}
