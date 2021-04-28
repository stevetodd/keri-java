package foundation.identity.keri.eventstorage.inmemory;

import foundation.identity.keri.KeyEventEscrow;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class InMemoryKeyEventEscrow implements KeyEventEscrow {

  private final Map<KeyEventCoordinates, List<KeyEvent>> isd = new HashMap<>();
  private final Map<DelegatingEventCoordinates, List<KeyEvent>> isp = new HashMap<>();

  @Override
  public Stream<KeyEvent> eventsAwaiting(KeyEventCoordinates dependency) {
    return this.isd.getOrDefault(dependency, Collections.emptyList()).stream();
  }

  @Override
  public Stream<KeyEvent> eventsAwaiting(DelegatingEventCoordinates dependency) {
    return this.isp.getOrDefault(dependency, Collections.emptyList()).stream();
  }

  @Override
  public void await(KeyEventCoordinates dependency, KeyEvent event) {
    this.isd.computeIfAbsent(dependency, k -> new ArrayList<>()).add(event);
  }

  @Override
  public void await(DelegatingEventCoordinates dependency, KeyEvent event) {
    this.isp.computeIfAbsent(dependency, k -> new ArrayList<>()).add(event);
  }

}
