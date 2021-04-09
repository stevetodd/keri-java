package foundation.identity.keri;

import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.KeyEventCoordinates;

import java.util.stream.Stream;

public interface KeyEventEscrow {

  KeyEventEscrow DISCARD = new DiscardingEscrow();

  Stream<Event> eventsAwaiting(KeyEventCoordinates dependency);

  Stream<Event> eventsAwaiting(DelegatingEventCoordinates dependency);

  void await(KeyEventCoordinates dependency, Event event);

  void await(DelegatingEventCoordinates dependency, Event event);

  final class DiscardingEscrow implements KeyEventEscrow {

    @Override
    public Stream<Event> eventsAwaiting(KeyEventCoordinates dependency) {
      return Stream.empty();
    }

    @Override
    public Stream<Event> eventsAwaiting(DelegatingEventCoordinates dependency) {
      return Stream.empty();
    }

    @Override
    public void await(KeyEventCoordinates dependency, Event event) {
    }

    @Override
    public void await(DelegatingEventCoordinates dependency, Event event) {
    }

  }

}
