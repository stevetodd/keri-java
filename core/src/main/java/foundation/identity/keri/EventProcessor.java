package foundation.identity.keri;

import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.event.DelegatedEstablishmentEvent;
import foundation.identity.keri.api.event.DelegatedInceptionEvent;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.internal.ImmutableIdentifierState;

import java.util.ArrayList;

import static java.util.Objects.requireNonNull;

public final class EventProcessor {

  /**
   * Computes the next {@link IdentifierState} from the currentState the next
   * event.
   *
   * @param currentState
   *     the state existing before the event
   * @param event
   *     the next event
   *
   * @return the identifier state
   */
  public IdentifierState apply(IdentifierState currentState, IdentifierEvent event) {
    if (event instanceof InceptionEvent) {
      if (currentState != null) {
        throw new IllegalArgumentException("currentState must not be passed for inception events");
      }
      currentState = initialState((InceptionEvent) event);
    }

    requireNonNull(currentState, "currentState is required");

    var signingThreshold = currentState.signingThreshold();
    var keys = currentState.keys();
    var nextKeyConfigugurationDigest = currentState.nextKeyConfigurationDigest();
    var witnessThreshold = currentState.witnessThreshold();
    var witnesses = currentState.witnesses();
    var lastEstablishmentEvent = currentState.lastEstablishmentEvent();

    if (event instanceof RotationEvent) {
      var re = (RotationEvent) event;
      signingThreshold = re.signingThreshold();
      keys = re.keys();
      nextKeyConfigugurationDigest = re.nextKeyConfiguration();
      witnessThreshold = re.witnessThreshold();

      witnesses = new ArrayList<>(witnesses);
      witnesses.removeAll(re.removedWitnesses());
      witnesses.addAll(re.addedWitnesses());

      lastEstablishmentEvent = re;
    }

    return new ImmutableIdentifierState(
        currentState.identifier(),
        signingThreshold,
        keys,
        nextKeyConfigugurationDigest.orElse(null),
        witnessThreshold,
        witnesses,
        currentState.configurationTraits(),
        event,
        lastEstablishmentEvent,
        currentState.delegatingIdentifier().orElse(null));
  }

  public IdentifierState initialState(InceptionEvent event) {
    var delegatingPrefix = event instanceof DelegatedInceptionEvent
                           ? ((DelegatedEstablishmentEvent) event).delegatingEvent().identifier()
                           : null;

    return new ImmutableIdentifierState(
        event.identifier(),
        event.signingThreshold(),
        event.keys(),
        event.nextKeyConfiguration().orElse(null),
        event.witnessThreshold(),
        event.witnesses(),
        event.configurationTraits(),
        event,
        event,
        delegatingPrefix);
  }

}
