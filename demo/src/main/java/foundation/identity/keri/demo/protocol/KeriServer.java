package foundation.identity.keri.demo.protocol;

import io.netty.channel.EventLoopGroup;
import io.netty.channel.group.ChannelGroup;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;
import reactor.netty.DisposableServer;
import reactor.netty.NettyInbound;
import reactor.netty.NettyOutbound;
import reactor.netty.channel.ChannelMetricsRecorder;
import reactor.netty.resources.LoopResources;
import reactor.netty.tcp.SslProvider;
import reactor.netty.transport.ServerTransport;
import reactor.util.Logger;
import reactor.util.Loggers;

import java.net.SocketAddress;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;

public abstract class KeriServer extends ServerTransport<KeriServer, KeriServerConfig> {

	static final Logger log = Loggers.getLogger(KeriServer.class);

	public static KeriServer create() {
		return KeriServerBind.INSTANCE;
	}

	@Override
	public KeriServer bindAddress(Supplier<? extends SocketAddress> bindAddressSupplier) {
		return super.bindAddress(bindAddressSupplier);
	}

	@Override
	public KeriServer channelGroup(ChannelGroup channelGroup) {
		return super.channelGroup(channelGroup);
	}

	@Override
	public KeriServer doOnBind(Consumer<? super KeriServerConfig> doOnBind) {
		return super.doOnBind(doOnBind);
	}

	@Override
	public KeriServer doOnBound(Consumer<? super DisposableServer> doOnBound) {
		return super.doOnBound(doOnBound);
	}

	@Override
	public KeriServer doOnConnection(Consumer<? super Connection> doOnConnection) {
		return super.doOnConnection(doOnConnection);
	}

	@Override
	public KeriServer doOnUnbound(Consumer<? super DisposableServer> doOnUnbound) {
		return super.doOnUnbound(doOnUnbound);
	}

	/**
	 * Attaches an I/O handler to react on a connected client
	 *
	 * @param handler
	 *     an I/O handler that can dispose underlying connection when
	 *     {@link Publisher} terminates.
	 *
	 * @return a new {@link KeriServer}
	 */
	public KeriServer handle(BiFunction<? super NettyInbound, ? super NettyOutbound, ? extends Publisher<Void>> handler) {
		Objects.requireNonNull(handler, "handler");
		return doOnConnection(new OnConnectionHandle(handler));
	}

	@Override
	public KeriServer host(String host) {
		return super.host(host);
	}

	@Override
	public KeriServer metrics(boolean enable) {
		return super.metrics(enable);
	}

	@Override
	public KeriServer metrics(boolean enable, Supplier<? extends ChannelMetricsRecorder> recorder) {
		return super.metrics(enable, recorder);
	}

	/**
	 * Removes any previously applied SSL configuration customization
	 *
	 * @return a new {@link KeriServer}
	 */
	public KeriServer noSSL() {
		if (configuration().isSecure()) {
			KeriServer dup = duplicate();
			dup.configuration().sslProvider = null;
			return dup;
		}
		return this;
	}

	@Override
	public KeriServer port(int port) {
		return super.port(port);
	}

	@Override
	public KeriServer runOn(EventLoopGroup eventLoopGroup) {
		return super.runOn(eventLoopGroup);
	}

	@Override
	public KeriServer runOn(LoopResources channelResources) {
		return super.runOn(channelResources);
	}

	@Override
	public KeriServer runOn(LoopResources loopResources, boolean preferNative) {
		return super.runOn(loopResources, preferNative);
	}

	/**
	 * Apply an SSL configuration customization via the passed builder. The builder
	 * will produce the {@link SslContext} to be passed to with a default value of
	 * {@code 10} seconds handshake timeout unless the environment property {@code
	 * reactor.netty.tcp.sslHandshakeTimeout} is set.
	 * <p>
	 * If {@link SelfSignedCertificate} needs to be used, the sample below can be
	 * used. Note that {@link SelfSignedCertificate} should not be used in production.
	 * <pre>
	 * {@code
	 *     SelfSignedCertificate cert = new SelfSignedCertificate();
	 *     SslContextBuilder sslContextBuilder =
	 *             SslContextBuilder.forServer(cert.certificate(), cert.privateKey());
	 *     secure(sslContextSpec -> sslContextSpec.sslContext(sslContextBuilder));
	 * }
	 * </pre>
	 *
	 * @param sslProviderBuilder
	 *     builder callback for further customization of SslContext.
	 *
	 * @return a new {@link KeriServer}
	 */
	public KeriServer secure(Consumer<? super SslProvider.SslContextSpec> sslProviderBuilder) {
		Objects.requireNonNull(sslProviderBuilder, "sslProviderBuilder");
		KeriServer dup = duplicate();
		SslProvider.SslContextSpec builder = SslProvider.builder();
		sslProviderBuilder.accept(builder);
		dup.configuration().sslProvider = ((SslProvider.Builder) builder).build();
		return dup;
	}

	/**
	 * Applies an SSL configuration via the passed {@link SslProvider}.
	 * <p>
	 * If {@link SelfSignedCertificate} needs to be used, the sample below can be
	 * used. Note that {@link SelfSignedCertificate} should not be used in production.
	 * <pre>
	 * {@code
	 *     SelfSignedCertificate cert = new SelfSignedCertificate();
	 *     SslContextBuilder sslContextBuilder =
	 *             SslContextBuilder.forServer(cert.certificate(), cert.privateKey());
	 *     secure(sslContextSpec -> sslContextSpec.sslContext(sslContextBuilder));
	 * }
	 * </pre>
	 *
	 * @param sslProvider
	 *     The provider to set when configuring SSL
	 *
	 * @return a new {@link KeriServer}
	 */
	public KeriServer secure(SslProvider sslProvider) {
		Objects.requireNonNull(sslProvider, "sslProvider");
		KeriServer dup = duplicate();
		dup.configuration().sslProvider = sslProvider;
		return dup;
	}

	/**
	 * Based on the actual configuration, returns a {@link Mono} that triggers:
	 * <ul>
	 *     <li>an initialization of the event loop groups</li>
	 *     <li>loads the necessary native libraries for the transport</li>
	 *     <li>loads the necessary native libraries for the security if there is such</li>
	 * </ul>
	 * By default, when method is not used, the {@code bind operation} absorbs the extra time needed to load resources.
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
	public KeriServer wiretap(boolean enable) {
		return super.wiretap(enable);
	}

	@Override
	public KeriServer wiretap(String category) {
		return super.wiretap(category);
	}

	@Override
	public KeriServer wiretap(String category, LogLevel level) {
		return super.wiretap(category, level);
	}

	static final class OnConnectionHandle implements Consumer<Connection> {

		final BiFunction<? super NettyInbound, ? super NettyOutbound, ? extends Publisher<Void>> handler;

		OnConnectionHandle(BiFunction<? super NettyInbound, ? super NettyOutbound, ? extends Publisher<Void>> handler) {
			this.handler = handler;
		}

		@Override
		public void accept(Connection c) {
			// if (log.isDebugEnabled()) {
			// 	log.debug(format(c.channel(), "Handler is being applied: {}"), handler);
			// }
			Mono.fromDirect(handler.apply(c.inbound(), c.outbound()))
					.subscribe(c.disposeSubscriber());
		}
	}
}
