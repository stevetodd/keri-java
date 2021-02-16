package foundation.identity.keri.demo.protocol;

import foundation.identity.keri.api.event.Event;
import reactor.core.publisher.Flux;
import reactor.netty.NettyInbound;

public interface EventInbound extends NettyInbound {

  default Flux<Event> receiveEvents() {
    return this.receiveObject().ofType(Event.class);
  }

}
