package foundation.identity.keri.demo.protocol;

import foundation.identity.keri.api.event.KeyEvent;
import reactor.core.publisher.Flux;
import reactor.netty.NettyInbound;

public interface EventInbound extends NettyInbound {

  default Flux<KeyEvent> receiveEvents() {
    return this.receiveObject().ofType(KeyEvent.class);
  }

}
