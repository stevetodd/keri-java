package foundation.identity.keri.demo.protocol;

import io.netty.channel.ChannelOption;
import io.netty.util.NetUtil;
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.transport.AddressUtils;

import java.util.Collections;

final class KeriClientConnect extends KeriClient {

	/**
	 * The default port for reactor-netty servers. Defaults to 12012 but can be tuned via
	 * the {@code PORT} <b>environment variable</b>.
	 */
	static final int DEFAULT_PORT = System.getenv("PORT") != null ? Integer.parseInt(System.getenv("PORT")) : 12012;
	final KeriClientConfig config;

	KeriClientConnect(ConnectionProvider provider) {
		this.config = new KeriClientConfig(
				provider,
				Collections.singletonMap(ChannelOption.AUTO_READ, false),
				() -> AddressUtils.createUnresolved(NetUtil.LOCALHOST.getHostAddress(), DEFAULT_PORT));
	}

	KeriClientConnect(KeriClientConfig config) {
		this.config = config;
	}

	@Override
	public KeriClientConfig configuration() {
		return config;
	}

	@Override
	protected KeriClient duplicate() {
		return new KeriClientConnect(new KeriClientConfig(config));
	}

}