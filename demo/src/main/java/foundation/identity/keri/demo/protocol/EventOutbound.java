package foundation.identity.keri.demo.protocol;

import foundation.identity.keri.api.event.KeyEvent;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.netty.NettyOutbound;

public interface EventOutbound extends NettyOutbound {

  default NettyOutbound sendEvent(KeyEvent event) {
    return this.sendObject(event);
  }

  default NettyOutbound sendEvent(Publisher<? extends KeyEvent> eventStream) {
    return this.sendObject(Flux.from(eventStream), o -> true);
  }

}
