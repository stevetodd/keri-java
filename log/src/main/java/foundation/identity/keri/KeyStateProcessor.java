package foundation.identity.keri;

import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.DelegatedEstablishmentEvent;
import foundation.identity.keri.api.event.DelegatedInceptionEvent;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.internal.ImmutableKeyState;

import java.util.ArrayList;

import static java.util.Objects.requireNonNull;

public final class KeyStateProcessor {

  public static KeyState apply(KeyState currentState, KeyEvent event) {
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

    return new ImmutableKeyState(
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

  public static KeyState initialState(InceptionEvent event) {
    var delegatingPrefix = event instanceof DelegatedInceptionEvent
        ? ((DelegatedEstablishmentEvent) event).delegatingEvent().identifier()
        : null;

    return new ImmutableKeyState(
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
