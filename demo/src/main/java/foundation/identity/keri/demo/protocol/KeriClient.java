package foundation.identity.keri.demo.protocol;

import foundation.identity.keri.api.event.KeyEvent;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.handler.logging.LogLevel;
import io.netty.resolver.AddressResolverGroup;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;
import reactor.netty.ConnectionObserver;
import reactor.netty.channel.ChannelMetricsRecorder;
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.resources.LoopResources;
import reactor.netty.tcp.TcpResources;
import reactor.netty.transport.ClientTransport;

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

	public KeriClient sendEvent(Publisher<? extends KeyEvent> events) {
		requireNonNull(events, "events");
		return this.doOnConnected(c -> ((KeriChannelOperations) c).sendEvent(events).then().subscribe());
	}

	public KeriClient sendEvent(KeyEvent event) {
		requireNonNull(event, "event");
		return this.doOnConnected(c -> ((KeriChannelOperations) c).sendEvent(Mono.just(event)).then().subscribe());
	}

	public KeriClient handle(BiFunction<? super EventInbound, ? super EventOutbound, ? extends Publisher<Void>> handler) {
		requireNonNull(handler, "handler");
		return this.doOnConnected(new OnConnectedHandle(handler));
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

	@Override
	public KeriClient wiretap(boolean enable) {
		return super.wiretap(enable);
	}

	@Override
	public KeriClient wiretap(String category) {
		return super.wiretap(category);
	}

	@Override
	public KeriClient wiretap(String category, LogLevel level) {
		return super.wiretap(category, level);
	}

	static final class OnConnectedHandle implements Consumer<Connection> {

		final BiFunction<? super EventInbound, ? super EventOutbound, ? extends Publisher<Void>> handler;

		OnConnectedHandle(BiFunction<? super EventInbound, ? super EventOutbound, ? extends Publisher<Void>> handler) {
			this.handler = handler;
		}

		@Override
		public void accept(Connection c) {
			Mono.fromDirect(this.handler.apply((EventInbound) c, (EventOutbound) c))
					.subscribe(c.disposeSubscriber());
		}

	}

}
