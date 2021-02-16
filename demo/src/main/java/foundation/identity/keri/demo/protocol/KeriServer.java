package foundation.identity.keri.demo.protocol;

import io.netty.channel.EventLoopGroup;
import io.netty.channel.group.ChannelGroup;
import io.netty.handler.logging.LogLevel;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;
import reactor.netty.DisposableServer;
import reactor.netty.channel.ChannelMetricsRecorder;
import reactor.netty.resources.LoopResources;
import reactor.netty.transport.ServerTransport;

import java.net.SocketAddress;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;

public abstract class KeriServer extends ServerTransport<KeriServer, KeriServerConfig> {

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
	public KeriServer handle(BiFunction<? super EventInbound, ? super EventOutbound, ? extends Publisher<Void>> handler) {
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

		final BiFunction<? super EventInbound, ? super EventOutbound, ? extends Publisher<Void>> handler;

		OnConnectionHandle(BiFunction<? super EventInbound, ? super EventOutbound, ? extends Publisher<Void>> handler) {
			this.handler = handler;
		}

		@Override
		public void accept(Connection c) {
			Mono.fromDirect(this.handler.apply((EventInbound) c.inbound(), (EventOutbound) c.outbound()))
					.subscribe(c.disposeSubscriber());
		}
	}
}
