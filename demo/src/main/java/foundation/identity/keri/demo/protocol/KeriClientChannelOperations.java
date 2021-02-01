package foundation.identity.keri.demo.protocol;

import reactor.netty.Connection;
import reactor.netty.ConnectionObserver;
import reactor.netty.NettyInbound;
import reactor.netty.NettyOutbound;
import reactor.netty.channel.ChannelOperations;

public class KeriClientChannelOperations<INBOUND extends NettyInbound, OUTBOUND extends NettyOutbound>
    extends ChannelOperations<INBOUND, OUTBOUND> {

  protected KeriClientChannelOperations(KeriClientChannelOperations<INBOUND, OUTBOUND> replaced) {
    super(replaced);
  }

  protected KeriClientChannelOperations(Connection connection, ConnectionObserver listener) {
    super(connection, listener);
  }

}
