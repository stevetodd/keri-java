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
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.resources.LoopResources;
import reactor.netty.tcp.SslProvider;
import reactor.netty.tcp.TcpResources;
import reactor.netty.transport.ClientTransportConfig;

import java.net.SocketAddress;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

public final class KeriClientConfig extends ClientTransportConfig<KeriClientConfig> {


  static final ChannelOperations.OnSetup DEFAULT_OPS = (ch, c, msg) -> new ChannelOperations<>(ch, c);
  static final LoggingHandler LOGGING_HANDLER = new LoggingHandler(KeriClient.class);
  /**
   * Default value whether the SSL debugging on the client side will be enabled/disabled,
   * fallback to SSL debugging disabled
   */
  static final boolean SSL_DEBUG = Boolean.parseBoolean(System.getProperty(ReactorNetty.SSL_CLIENT_DEBUG, "false"));
  SslProvider sslProvider;


  // Protected/Package private write API

  KeriClientConfig(ConnectionProvider connectionProvider, Map<ChannelOption<?>, ?> options,
                   Supplier<? extends SocketAddress> remoteAddress) {
    super(connectionProvider, options, remoteAddress);
  }

  KeriClientConfig(KeriClientConfig parent) {
    super(parent);
    this.sslProvider = parent.sslProvider;
  }

  @Override
  public int channelHash() {
    return Objects.hash(super.channelHash(), sslProvider);
  }

  @Override
  public ChannelOperations.OnSetup channelOperationsProvider() {
    return DEFAULT_OPS;
  }

  /**
   * Return true if that {@link KeriClient} secured via SSL transport
   *
   * @return true if that {@link KeriClient} secured via SSL transport
   */
  public final boolean isSecure() {
    return sslProvider != null;
  }

  /**
   * Return the current {@link SslProvider} if that {@link KeriClient} secured via SSL
   * transport or null
   *
   * @return the current {@link SslProvider} if that {@link KeriClient} secured via SSL
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
    return MicrometerKeriClientMetricsRecorder.INSTANCE;
  }

  @Override
  protected ChannelPipelineConfigurer defaultOnChannelInit() {
    ChannelPipelineConfigurer _default = super.defaultOnChannelInit();
    if (sslProvider != null) {
      return _default.then(new KeriClientChannelInitializer(sslProvider));
    } else {
      return _default;
    }
  }

  static final class MicrometerKeriClientMetricsRecorder extends MicrometerChannelMetricsRecorder {

    static final MicrometerKeriClientMetricsRecorder INSTANCE = new MicrometerKeriClientMetricsRecorder();

    MicrometerKeriClientMetricsRecorder() {
      super("keri.client", "tcp");
    }
  }

  static final class KeriClientChannelInitializer implements ChannelPipelineConfigurer {

    final SslProvider sslProvider;

    KeriClientChannelInitializer(SslProvider sslProvider) {
      this.sslProvider = sslProvider;
    }

    @Override
    public void onChannelInit(ConnectionObserver connectionObserver, Channel channel, SocketAddress remoteAddress) {
      sslProvider.addSslHandler(channel, remoteAddress, SSL_DEBUG);
    }
  }
}
