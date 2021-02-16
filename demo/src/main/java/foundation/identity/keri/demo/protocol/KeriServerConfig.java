package foundation.identity.keri.demo.protocol;

import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.handler.logging.LoggingHandler;
import reactor.netty.ChannelPipelineConfigurer;
import reactor.netty.ConnectionObserver;
import reactor.netty.NettyPipeline;
import reactor.netty.channel.ChannelMetricsRecorder;
import reactor.netty.channel.ChannelOperations;
import reactor.netty.channel.MicrometerChannelMetricsRecorder;
import reactor.netty.resources.LoopResources;
import reactor.netty.tcp.TcpResources;
import reactor.netty.transport.ServerTransportConfig;

import java.net.SocketAddress;
import java.util.Map;
import java.util.function.Supplier;

public class KeriServerConfig extends ServerTransportConfig<KeriServerConfig> {

  static final ChannelOperations.OnSetup DEFAULT_OPS = (ch, c, msg) -> new KeriChannelOperations(ch, c);
  static final LoggingHandler LOGGING_HANDLER = new LoggingHandler(KeriServer.class);

  KeriServerConfig(Map<ChannelOption<?>, ?> options, Map<ChannelOption<?>, ?> childOptions,
                   Supplier<? extends SocketAddress> localAddress) {
    super(options, childOptions, localAddress);
  }

  KeriServerConfig(KeriServerConfig parent) {
    super(parent);
  }

  @Override
  public ChannelOperations.OnSetup channelOperationsProvider() {
    return DEFAULT_OPS;
  }

  @Override
  protected LoggingHandler defaultLoggingHandler() {
    return LOGGING_HANDLER;
  }

  @Override
  protected LoopResources defaultLoopResources() {
    return TcpResources.get();
  }

  @Override
  protected ChannelMetricsRecorder defaultMetricsRecorder() {
    return MicrometerKeriServerMetricsRecorder.INSTANCE;
  }

  @Override
  protected ChannelPipelineConfigurer defaultOnChannelInit() {
    return super.defaultOnChannelInit()
        .then(new KeriServerChannelInitializer());
  }

  static final class MicrometerKeriServerMetricsRecorder extends MicrometerChannelMetricsRecorder {

    static final MicrometerKeriServerMetricsRecorder INSTANCE = new MicrometerKeriServerMetricsRecorder();

    MicrometerKeriServerMetricsRecorder() {
      super(reactor.netty.Metrics.TCP_SERVER_PREFIX, "tcp");
    }
  }

  static final class KeriServerChannelInitializer implements ChannelPipelineConfigurer {

    @Override
    public void onChannelInit(ConnectionObserver connectionObserver, Channel channel, SocketAddress remoteAddress) {
      channel.pipeline()
          .addBefore(NettyPipeline.ReactiveBridge, "keri-decoder", new KeriEventDecoder())
          .addBefore(NettyPipeline.ReactiveBridge, "keri-encoder", new KeriEventEncoder());
    }
  }
}
