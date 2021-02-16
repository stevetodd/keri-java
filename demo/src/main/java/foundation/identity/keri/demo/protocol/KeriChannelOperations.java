package foundation.identity.keri.demo.protocol;

import reactor.netty.Connection;
import reactor.netty.ConnectionObserver;
import reactor.netty.channel.ChannelOperations;

public class KeriChannelOperations
    extends ChannelOperations<EventInbound, EventOutbound>
    implements EventInbound, EventOutbound {

  protected KeriChannelOperations(KeriChannelOperations replaced) {
    super(replaced);
  }

  protected KeriChannelOperations(Connection connection, ConnectionObserver listener) {
    super(connection, listener);
  }

  static void discard(KeriChannelOperations c) {
    if (!c.isInboundDisposed()) {
      c.discard();
    }
  }

}
