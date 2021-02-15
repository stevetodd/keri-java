package foundation.identity.keri;

import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.DelegatedEstablishmentEvent;
import foundation.identity.keri.api.event.DelegatedRotationEvent;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;
import foundation.identity.keri.api.identifier.SelfSigningIdentifier;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.crypto.SignatureOperations;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static foundation.identity.keri.QualifiedBase64.qb64;

public final class EventValidator {

  public void validate(IdentifierState state, Event event) {
    if (event instanceof IdentifierEvent) {
      var ide = (IdentifierEvent) event;

      if (!(event instanceof InceptionEvent)) {
        requireNonNull(state, "state is required for non-inception events");

        // prefix
        require(state.identifier().equals(ide.identifier()), "state and event prefix must match");

        // sequence number
        require(ide.sequenceNumber().compareTo(BigInteger.ZERO) > 0,
            "non-inception events must have a sequence number greater than 0 (given: %s)", ide.sequenceNumber());

        require(ide.sequenceNumber().subtract(BigInteger.ONE).equals(state.lastEvent().sequenceNumber()),
            "sequence number must one greater than previous event (last: %s, event: %s",
            state.lastEvent().sequenceNumber(), ide.sequenceNumber());

        // previous (digest)
        require(matchingDigests(state.lastEvent(), ide.previous()),
            "previous event digest must match digest of the last event in state");

      }

      if (event instanceof EstablishmentEvent) {
        var ee = (EstablishmentEvent) event;

        // signature
        requireValidEventSignatures(state, ee);

        require(ee.signatures().size() >= ee.signingThreshold(),
            "count of event signatures must be greater than or equal to signing threshold (count: %s, threshold: %s)",
            ee.signatures().size(), ee.signingThreshold());

        require(ee.identifier().transferable() || (ee.nextKeyConfiguration().isEmpty()),
            "non-transferrable prefix must not have a next key configuration");

        if (event instanceof DelegatedEstablishmentEvent) {
          var dee = (DelegatedEstablishmentEvent) ee;
          requireNonNull(dee.delegatingEvent(), "delegating event location required for delegated establishment events");

          // TODO validate seal

          require(state.delegatingIdentifier().isPresent(),
              "delegated establishment events only permitted for delegated identifiers");

          require(dee.delegatingEvent().identifier().equals(state.delegatingIdentifier().get()),
              "delegated rotation seal identifier must be the same as the delegator in state "
                  + "(given: state.delegator: %s, rotation.seal.identity: %s)",
              () -> qb64(state.delegatingIdentifier().get()), () -> qb64(dee.delegatingEvent().identifier()));
        }

        require(ee.signingThreshold() > 0, "signing threshold must be greater than 0 (given: %s)", ee.signingThreshold());

        require(ee.signingThreshold() <= ee.keys().size(),
            "signing threshold must be less than or equal to the number of keys (given: threshold: %s, keys: %s)",
            ee.signingThreshold(), ee.keys().size());

        require(!ee.keys().isEmpty(), "at least one key is required");

        if (event instanceof InceptionEvent) {
          var ie = (InceptionEvent) event;

          requireValidIdentifier(ie);

          // sequence number
          require(ie.sequenceNumber().equals(BigInteger.ZERO),
              "sequence number for inception event must be 0 (given: %s)", ie.sequenceNumber());

          // witness configuration
          if (ie.witnesses().isEmpty()) {
            require(ie.witnessThreshold() == 0, "witness threshold must be 0 if no witnesses are provided");
          } else {
            require(Set.of(ie.witnesses()).size() == ie.witnesses().size(), "witness set must not have duplicates");

            require(ie.witnessThreshold() > 0,
                "witness threshold must be greater than 0 if witnesses are provided (given: threshold: %s, witnesses: %s",
                ie.witnessThreshold(), ie.witnesses().size());

            require(ie.witnessThreshold() <= ie.witnesses().size(),
                "witness threshold must be less than or equal to the number of witnesses (given: threshold: %s, witnesses: %s",
                ie.witnessThreshold(), ie.witnesses().size());
          }

        } else if (event instanceof RotationEvent) {
          var re = (RotationEvent) event;

          requireNonNull(state.transferrable(), "rotation only permitted when in transferrable state");

          require(!state.delegated() || (event instanceof DelegatedRotationEvent),
              "delegated identifiers must use delegated rotation event type");

          // nextKeyDigest
          require(state.nextKeyConfigurationDigest().isPresent(),
              "previous event must have specified next key configuration to permit rotation");

          var keyConfigurationDigest = KeyConfigurationDigester.digest(re.signingThreshold(), re.keys(),
              state.nextKeyConfigurationDigest().get().algorithm());
          require(keyConfigurationDigest.equals(state.nextKeyConfigurationDigest().get()),
              "digest of signing threshold and keys must match digest in previous establishment event");

          // witnesses
          if (!re.removedWitnesses().isEmpty()) {
            require(Set.of(re.removedWitnesses()).size() == re.removedWitnesses().size(),
                "removed witnesses must not have duplicates");
          }
          if (!re.addedWitnesses().isEmpty()) {
            require(Set.of(re.addedWitnesses()).size() == re.addedWitnesses().size(),
                "added witnesses must not have duplicates");
          }
          require(state.witnesses().containsAll(re.removedWitnesses()),
              "removed witnesses must all be present in state's witness set");

          var addRemoveIntersects = new HashSet<>(re.addedWitnesses()).removeAll(re.removedWitnesses());
          require(!addRemoveIntersects, "added and removed witnesses must be mutually exclusive");

          var currentAddedIntersects = new HashSet<>(re.addedWitnesses()).removeAll(state.witnesses());
          require(!currentAddedIntersects, "added witnesses must not be present in state's witness set");

          var newWitnesses = new HashSet<>(state.witnesses());
          newWitnesses.addAll(re.addedWitnesses());
          if (newWitnesses.isEmpty()) {
            require(re.witnessThreshold() == 0, "witness threshold must be 0 if no witnesses are provided");
          } else {
            require(re.witnessThreshold() > 0,
                "witness threshold must be greater than 0 if witnesses are provided (given: threshold: %s, witnesses: %s",
                re.witnessThreshold(), newWitnesses.size());

            require(re.witnessThreshold() <= newWitnesses.size(),
                "witness threshold must be less than or equal to the number of witnesses (given: threshold: %s, witnesses: %s",
                re.witnessThreshold(), newWitnesses.size());
          }

          // TODO validate recovery events
        }
      } else if (event instanceof InteractionEvent) {
        var xe = (InteractionEvent) event;

        require(!state.configurationTraits().contains(ConfigurationTrait.ESTABLISHMENT_EVENTS_ONLY),
            "interaction events only permitted when identifier is not configured for establishment events only");

      } else {
        throw new EventValidationException("Unknown event type: " + event.type() + "/" + event.getClass());
      }
    }
  }

  private void requireValidIdentifier(InceptionEvent event) {
    if (event.identifier() instanceof BasicIdentifier) {

      require(event.keys().size() == 1, "basic prefixes can only have a single key");

      require(((BasicIdentifier) event.identifier()).publicKey().equals(event.keys().get(0)),
          "basic prefix key must match event key");

    } else if (event.identifier() instanceof SelfAddressingIdentifier) {
      var sap = (SelfAddressingIdentifier) event.identifier();
      var ops = DigestOperations.lookup(sap.digest().algorithm());
      var digest = ops.digest(event.inceptionStatement());

      require(Digest.equals(sap.digest(), digest),
          "self-addressing prefix digest must match digest of inception event");

    } else if (event.identifier() instanceof SelfSigningIdentifier) {

      require(event.keys().size() == 1,
          "self-signing prefixes can only have a single key");

      var ssp = (SelfSigningIdentifier) event.identifier();
      var ops = SignatureOperations.lookup(event.keys().get(0));

      require(ops.verify(event.inceptionStatement(), ssp.signature(), event.keys().get(0)),
          "self-signing prefix signature must verify against event");

    } else {
      throw new IllegalArgumentException("Unknown prefix type: " + event.identifier().getClass());
    }
  }

  private boolean matchingDigests(IdentifierEvent lastEvent, IdentifierEventCoordinatesWithDigest newEventPrevious) {
    var algorithm = newEventPrevious.digest().algorithm();
    var ops = DigestOperations.lookup(algorithm);

    return ops.digest(lastEvent.bytes()).equals(newEventPrevious.digest());
  }

  private void requireValidEventSignatures(IdentifierState state, IdentifierEvent event) {
    EstablishmentEvent lastEstablishmentEvent;
    if (event instanceof EstablishmentEvent) {
      lastEstablishmentEvent = (EstablishmentEvent) event;
    } else if (state != null) {
      lastEstablishmentEvent = state.lastEstablishmentEvent();
    } else {
      throw new IllegalArgumentException("state is required to validate signatures on a non-establishment event");
    }

    for (var signature : event.signatures()) {
      var ops = SignatureOperations.lookup(signature.signature().algorithm());
      var eventCoords = signature.event();
      var publicKey = lastEstablishmentEvent.keys().get(signature.keyIndex());

      require(ops.verify(event.bytes(), signature.signature(), publicKey),
          "event signatures must validate (i: %s, s: %s, d: %s, index: %s)",
          event.identifier(), event.sequenceNumber(), eventCoords.digest(),
          signature.keyIndex());
    }
  }

  private void requireNonNull(Object o, String message) {
    require(o != null, message);
  }

  private void require(boolean valid, String message, Supplier<?>... formatValues) {
    if (!valid) {
      var supplied = Stream.of(formatValues)
          .map(Supplier::get)
          .toArray();
      throw new EventValidationException(String.format(message, supplied));
    }
  }

  private void require(boolean valid, String message, Object... formatValues) {
    if (!valid) {
      throw new EventValidationException(String.format(message, formatValues));
    }
  }

}
