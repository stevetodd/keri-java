package foundation.identity.keri;

import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;

import java.util.stream.Stream;

public interface KeyEventEscrow {

  KeyEventEscrow DISCARD = new DiscardingEscrow();

  Stream<KeyEvent> eventsAwaiting(KeyEventCoordinates dependency);

  Stream<KeyEvent> eventsAwaiting(DelegatingEventCoordinates dependency);

  void await(KeyEventCoordinates dependency, KeyEvent event);

  void await(DelegatingEventCoordinates dependency, KeyEvent event);

  final class DiscardingEscrow implements KeyEventEscrow {

    @Override
    public Stream<KeyEvent> eventsAwaiting(KeyEventCoordinates dependency) {
      return Stream.empty();
    }

    @Override
    public Stream<KeyEvent> eventsAwaiting(DelegatingEventCoordinates dependency) {
      return Stream.empty();
    }

    @Override
    public void await(KeyEventCoordinates dependency, KeyEvent event) {
    }

    @Override
    public void await(DelegatingEventCoordinates dependency, KeyEvent event) {
    }

  }

}
