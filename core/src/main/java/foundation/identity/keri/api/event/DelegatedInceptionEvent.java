package foundation.identity.keri.api.event;

public interface DelegatedInceptionEvent extends InceptionEvent, DelegatedEstablishmentEvent {

  @Override
  default EventType type() {
    return EventType.DELEGATED_INCEPTION;
  }

}
