package foundation.identity.keri.api.event;

import java.util.Set;

public enum EventType {
  INCEPTION,
  ROTATION,

  INTERACTION,

  DELEGATED_INCEPTION,
  DELEGATED_ROTATION,

  RECEIPT,
  RECEIPT_FROM_TRANSFERRABLE;

  public static final Set<EventType> DELEGATED_EVENTS = Set.of(DELEGATED_INCEPTION, DELEGATED_ROTATION);
  public static final Set<EventType> ESTABLISHMENT_EVENTS = Set.of(
      INCEPTION, ROTATION, DELEGATED_INCEPTION, DELEGATED_ROTATION);

}
