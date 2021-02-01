package foundation.identity.keri.demo;

import foundation.identity.keri.api.event.Event;

@FunctionalInterface
public interface EventHandler {

  void handle(Event event);

}
