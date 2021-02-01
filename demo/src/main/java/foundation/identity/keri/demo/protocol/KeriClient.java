package foundation.identity.keri.demo.protocol;

import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.resolver.AddressResolverGroup;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;
import reactor.netty.ConnectionObserver;
import reactor.netty.NettyInbound;
import reactor.netty.NettyOutbound;
import reactor.netty.channel.ChannelMetricsRecorder;
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.resources.LoopResources;
import reactor.netty.tcp.SslProvider;
import reactor.netty.tcp.TcpResources;
import reactor.netty.transport.ClientTransport;
import reactor.netty.transport.ProxyProvider;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

public abstract class KeriClient extends ClientTransport<KeriClient, KeriClientConfig> {

	/**
	 * Prepare a pooled {@link KeriClient}
	 *
	 * @return a {@link KeriClient}
	 */
	public static KeriClient create() {
		return create(TcpResources.get());
	}


	/**
	 * Prepare a {@link KeriClient}
	 *
	 * @param provider
	 *     a {@link ConnectionProvider} to acquire connections
	 *
	 * @return a {@link KeriClient}
	 */
	public static KeriClient create(ConnectionProvider provider) {
		requireNonNull(provider, "provider");
		return new KeriClientConnect(provider);
	}

	/**
	 * Prepare a non pooled {@link KeriClient}
	 *
	 * @return a {@link KeriClient}
	 */
	public static KeriClient newConnection() {
		return create(ConnectionProvider.newConnection());
	}

	public static void main(String[] args) throws InterruptedException {
		var client = KeriClient.create()
				.remoteAddress(() -> new InetSocketAddress("127.0.0.1", 5620))
				.wiretap("client", LogLevel.INFO)
				.connectNow()
				.outbound()
				.sendString(Mono.just("hello"))
				.then()
				.subscribe();
		Thread.sleep(10 * 1000);
	}

	@Override
	public KeriClient bindAddress(Supplier<? extends SocketAddress> bindAddressSupplier) {
		return super.bindAddress(bindAddressSupplier);
	}

	@Override
	public Mono<? extends Connection> connect() {
		return super.connect();
	}

	@Override
	public final Connection connectNow() {
		return super.connectNow();
	}

	@Override
	public final Connection connectNow(Duration timeout) {
		return super.connectNow(timeout);
	}

	@Override
	public KeriClient doOnConnect(Consumer<? super KeriClientConfig> doOnConnect) {
		return super.doOnConnect(doOnConnect);
	}

	@Override
	public KeriClient doOnConnected(Consumer<? super Connection> doOnConnected) {
		return super.doOnConnected(doOnConnected);
	}

	@Override
	public KeriClient doOnDisconnected(Consumer<? super Connection> doOnDisconnected) {
		return super.doOnDisconnected(doOnDisconnected);
	}

	/**
	 * Attach an IO handler to react on connected client
	 *
	 * @param handler
	 *     an IO handler that can dispose underlying connection when {@link
	 *     Publisher} terminates.
	 *
	 * @return a new {@link KeriClient}
	 */
	public KeriClient handle(BiFunction<? super NettyInbound, ? super NettyOutbound, ? extends Publisher<Void>> handler) {
		requireNonNull(handler, "handler");
		return doOnConnected(new OnConnectedHandle(handler));
	}

	@Override
	public KeriClient host(String host) {
		return super.host(host);
	}

	@Override
	public KeriClient metrics(boolean enable) {
		return super.metrics(enable);
	}

	@Override
	public KeriClient metrics(boolean enable, Supplier<? extends ChannelMetricsRecorder> recorder) {
		return super.metrics(enable, recorder);
	}

	@Override
	public KeriClient noProxy() {
		return super.noProxy();
	}

	/**
	 * Remove any previously applied SSL configuration customization
	 *
	 * @return a new {@link KeriClient}
	 */
	public KeriClient noSSL() {
		if (configuration().isSecure()) {
			KeriClient dup = duplicate();
			dup.configuration().sslProvider = null;
			return dup;
		}
		return this;
	}

	@Override
	public KeriClient observe(ConnectionObserver observer) {
		return super.observe(observer);
	}

	@Override
	public <O> KeriClient option(ChannelOption<O> key, O value) {
		return super.option(key, value);
	}

	@Override
	public KeriClient port(int port) {
		return super.port(port);
	}

	@Override
	public KeriClient proxy(Consumer<? super ProxyProvider.TypeSpec> proxyOptions) {
		return super.proxy(proxyOptions);
	}

	@Override
	public KeriClient remoteAddress(Supplier<? extends SocketAddress> remoteAddressSupplier) {
		return super.remoteAddress(remoteAddressSupplier);
	}

	@Override
	public KeriClient resolver(AddressResolverGroup<?> resolver) {
		return super.resolver(resolver);
	}

	@Override
	public KeriClient runOn(EventLoopGroup eventLoopGroup) {
		return super.runOn(eventLoopGroup);
	}

	@Override
	public KeriClient runOn(LoopResources channelResources) {
		return super.runOn(channelResources);
	}

	@Override
	public KeriClient runOn(LoopResources loopResources, boolean preferNative) {
		return super.runOn(loopResources, preferNative);
	}

	/**
	 * Enable default sslContext support. The default {@link SslContext} will be
	 * assigned to
	 * with a default value of {@code 10} seconds handshake timeout unless
	 * the environment property {@code reactor.netty.tcp.sslHandshakeTimeout} is set.
	 *
	 * @return a new {@link KeriClient}
	 */
	public KeriClient secure() {
		KeriClient dup = duplicate();
		dup.configuration().sslProvider = SslProvider.defaultClientProvider();
		return dup;
	}

	/**
	 * Apply an SSL configuration customization via the passed builder. The builder
	 * will produce the {@link SslContext} to be passed to with a default value of
	 * {@code 10} seconds handshake timeout unless the environment property {@code
	 * reactor.netty.tcp.sslHandshakeTimeout} is set.
	 *
	 * @param sslProviderBuilder
	 *     builder callback for further customization of SslContext.
	 *
	 * @return a new {@link KeriClient}
	 */
	public KeriClient secure(Consumer<? super SslProvider.SslContextSpec> sslProviderBuilder) {
		requireNonNull(sslProviderBuilder, "sslProviderBuilder");
		KeriClient dup = duplicate();
		SslProvider.SslContextSpec builder = SslProvider.builder();
		sslProviderBuilder.accept(builder);
		dup.configuration().sslProvider = ((SslProvider.Builder) builder).build();
		return dup;
	}

	/**
	 * Apply an SSL configuration via the passed {@link SslProvider}.
	 *
	 * @param sslProvider
	 *     The provider to set when configuring SSL
	 *
	 * @return a new {@link KeriClient}
	 */
	public KeriClient secure(SslProvider sslProvider) {
		requireNonNull(sslProvider, "sslProvider");
		KeriClient dup = duplicate();
		dup.configuration().sslProvider = sslProvider;
		return dup;
	}

	/**
	 * Based on the actual configuration, returns a {@link Mono} that triggers:
	 * <ul>
	 *     <li>an initialization of the event loop group</li>
	 *     <li>an initialization of the host name resolver</li>
	 *     <li>loads the necessary native libraries for the transport</li>
	 *     <li>loads the necessary native libraries for the security if there is such</li>
	 * </ul>
	 * By default, when method is not used, the {@code connect operation} absorbs the extra time needed to load resources.
	 *
	 * @return a {@link Mono} representing the completion of the warmup
	 *
	 * @since 1.0.3
	 */
	@Override
	public Mono<Void> warmup() {
		return Mono.when(
				super.warmup(),
				Mono.fromRunnable(() -> {
					SslProvider provider = configuration().sslProvider();
					if (provider != null && !(provider.getSslContext() instanceof JdkSslContext)) {
						OpenSsl.version();
					}
				}));
	}

	@Override
	public KeriClient wiretap(boolean enable) {
		return super.wiretap(enable);
	}

	@Override
	public KeriClient wiretap(String category) {
		return super.wiretap(category);
	}

	//static final Logger log = Loggers.getLogger(KeriClient.class);

	@Override
	public KeriClient wiretap(String category, LogLevel level) {
		return super.wiretap(category, level);
	}

	static final class OnConnectedHandle implements Consumer<Connection> {

		final BiFunction<? super NettyInbound, ? super NettyOutbound, ? extends Publisher<Void>> handler;

		OnConnectedHandle(BiFunction<? super NettyInbound, ? super NettyOutbound, ? extends Publisher<Void>> handler) {
			this.handler = handler;
		}

		@Override
		public void accept(Connection c) {
			//if (log.isDebugEnabled()) {
			//	log.debug(format(c.channel(), "Handler is being applied: {}"), handler);
			//}

			Mono.fromDirect(handler.apply((NettyInbound) c, (NettyOutbound) c))
					.subscribe(c.disposeSubscriber());
		}
	}


}
