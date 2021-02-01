package foundation.identity.keri.demo.protocol;

import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.handler.logging.LoggingHandler;
import reactor.netty.ChannelPipelineConfigurer;
import reactor.netty.ConnectionObserver;
import reactor.netty.ReactorNetty;
import reactor.netty.channel.ChannelMetricsRecorder;
import reactor.netty.channel.ChannelOperations;
import reactor.netty.channel.MicrometerChannelMetricsRecorder;
import reactor.netty.resources.LoopResources;
import reactor.netty.tcp.SslProvider;
import reactor.netty.tcp.TcpResources;
import reactor.netty.transport.ServerTransportConfig;

import java.net.SocketAddress;
import java.util.Map;
import java.util.function.Supplier;

public class KeriServerConfig extends ServerTransportConfig<KeriServerConfig> {


  static final ChannelOperations.OnSetup DEFAULT_OPS = (ch, c, msg) -> new ChannelOperations<>(ch, c);
  static final LoggingHandler LOGGING_HANDLER = new LoggingHandler(KeriServer.class);
  /**
   * Default value whether the SSL debugging on the server side will be enabled/disabled,
   * fallback to SSL debugging disabled
   */
  static final boolean SSL_DEBUG = Boolean.parseBoolean(System.getProperty(ReactorNetty.SSL_SERVER_DEBUG, "false"));


  // Protected/Package private write API
  SslProvider sslProvider;

  KeriServerConfig(Map<ChannelOption<?>, ?> options, Map<ChannelOption<?>, ?> childOptions,
                   Supplier<? extends SocketAddress> localAddress) {
    super(options, childOptions, localAddress);
  }

  KeriServerConfig(KeriServerConfig parent) {
    super(parent);
    this.sslProvider = parent.sslProvider;
  }

  @Override
  public ChannelOperations.OnSetup channelOperationsProvider() {
    return DEFAULT_OPS;
  }

  /**
   * Returns true if that {@link KeriServer} secured via SSL transport
   *
   * @return true if that {@link KeriServer} secured via SSL transport
   */
  public final boolean isSecure() {
    return sslProvider != null;
  }

  /**
   * Returns the current {@link SslProvider} if that {@link KeriServer} secured via SSL
   * transport or null.
   *
   * @return the current {@link SslProvider} if that {@link KeriServer} secured via SSL
   * transport or null
   */
  public SslProvider sslProvider() {
    return sslProvider;
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
    ChannelPipelineConfigurer _default = super.defaultOnChannelInit();
    if (sslProvider != null) {
      return _default.then(new KeriServerChannelInitializer(sslProvider));
    } else {
      return _default;
    }
  }

  static final class MicrometerKeriServerMetricsRecorder extends MicrometerChannelMetricsRecorder {

    static final MicrometerKeriServerMetricsRecorder INSTANCE = new MicrometerKeriServerMetricsRecorder();

    MicrometerKeriServerMetricsRecorder() {
      super(reactor.netty.Metrics.TCP_SERVER_PREFIX, "tcp");
    }
  }

  static final class KeriServerChannelInitializer implements ChannelPipelineConfigurer {

    final SslProvider sslProvider;

    KeriServerChannelInitializer(SslProvider sslProvider) {
      this.sslProvider = sslProvider;
    }

    @Override
    public void onChannelInit(ConnectionObserver connectionObserver, Channel channel, SocketAddress remoteAddress) {
      sslProvider.addSslHandler(channel, remoteAddress, SSL_DEBUG);
    }
  }
}
