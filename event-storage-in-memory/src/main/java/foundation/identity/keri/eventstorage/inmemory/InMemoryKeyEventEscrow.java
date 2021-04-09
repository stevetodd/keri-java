package foundation.identity.keri.eventstorage.inmemory;

import foundation.identity.keri.KeyEventEscrow;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class InMemoryKeyEventEscrow implements KeyEventEscrow {

  private final Map<IdentifierEventCoordinatesWithDigest, List<Event>> isd = new HashMap<>();
  private final Map<DelegatingEventCoordinates, List<Event>> isp = new HashMap<>();

  @Override
  public Stream<Event> eventsAwaiting(IdentifierEventCoordinatesWithDigest dependency) {
    return this.isd.getOrDefault(dependency, Collections.emptyList()).stream();
  }

  @Override
  public Stream<Event> eventsAwaiting(DelegatingEventCoordinates dependency) {
    return this.isp.getOrDefault(dependency, Collections.emptyList()).stream();
  }

  @Override
  public void await(IdentifierEventCoordinatesWithDigest dependency, Event event) {
    this.isd.computeIfAbsent(dependency, k -> new ArrayList<>()).add(event);
  }

  @Override
  public void await(DelegatingEventCoordinates dependency, Event event) {
    this.isp.computeIfAbsent(dependency, k -> new ArrayList<>()).add(event);
  }

}
