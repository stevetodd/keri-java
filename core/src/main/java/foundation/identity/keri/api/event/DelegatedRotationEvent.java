package foundation.identity.keri.api.event;

public interface DelegatedRotationEvent extends RotationEvent, DelegatedEstablishmentEvent {

  @Override
  default EventType type() {
    return EventType.DELEGATED_ROTATION;
  }

}
