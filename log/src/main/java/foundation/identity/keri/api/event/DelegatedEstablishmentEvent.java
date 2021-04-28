package foundation.identity.keri.api.event;

public interface DelegatedEstablishmentEvent extends EstablishmentEvent {

  DelegatingEventCoordinates delegatingEvent();

}
