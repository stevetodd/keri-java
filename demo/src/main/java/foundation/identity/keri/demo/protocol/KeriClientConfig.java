package foundation.identity.keri.demo.protocol;

import foundation.identity.keri.api.event.KeyEvent;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.handler.logging.LoggingHandler;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.netty.ChannelPipelineConfigurer;
import reactor.netty.ConnectionObserver;
import reactor.netty.NettyPipeline;
import reactor.netty.channel.ChannelMetricsRecorder;
import reactor.netty.channel.ChannelOperations;
import reactor.netty.channel.MicrometerChannelMetricsRecorder;
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.resources.LoopResources;
import reactor.netty.tcp.TcpResources;
import reactor.netty.transport.ClientTransportConfig;

import java.net.SocketAddress;
import java.util.Map;
import java.util.function.Supplier;

public final class KeriClientConfig extends ClientTransportConfig<KeriClientConfig> {

  static final ChannelOperations.OnSetup DEFAULT_OPS = (ch, c, msg) -> new KeriChannelOperations(ch, c);
  static final LoggingHandler LOGGING_HANDLER = new LoggingHandler(KeriClient.class);

  Publisher<KeyEvent> eventsToSend = Flux.empty();

  KeriClientConfig(ConnectionProvider connectionProvider, Map<ChannelOption<?>, ?> options,
                   Supplier<? extends SocketAddress> remoteAddress) {
    super(connectionProvider, options, remoteAddress);
  }

  KeriClientConfig(KeriClientConfig parent) {
    super(parent);
    this.eventsToSend = parent.eventsToSend;
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
    return MicrometerKeriClientMetricsRecorder.INSTANCE;
  }

  @Override
  protected ChannelPipelineConfigurer defaultOnChannelInit() {
    return super.defaultOnChannelInit()
        .then(new KeriClientChannelInitializer());
  }

  static final class MicrometerKeriClientMetricsRecorder extends MicrometerChannelMetricsRecorder {

    static final MicrometerKeriClientMetricsRecorder INSTANCE = new MicrometerKeriClientMetricsRecorder();

    MicrometerKeriClientMetricsRecorder() {
      super("keri.client", "tcp");
    }
  }

  static final class KeriClientChannelInitializer implements ChannelPipelineConfigurer {
    @Override
    public void onChannelInit(ConnectionObserver connectionObserver, Channel channel, SocketAddress remoteAddress) {
      channel.pipeline()
          .addBefore(NettyPipeline.ReactiveBridge, "keri-decoder", new KeriEventDecoder())
          .addBefore(NettyPipeline.ReactiveBridge, "keri-encoder", new KeriEventEncoder());
    }
  }

}
