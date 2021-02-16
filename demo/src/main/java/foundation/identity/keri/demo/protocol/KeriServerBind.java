package foundation.identity.keri.demo.protocol;

import io.netty.channel.ChannelOption;

import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

final class KeriServerBind extends KeriServer {
	static final KeriServerBind INSTANCE = new KeriServerBind();
	static final int DEFAULT_PORT = 0;
	final KeriServerConfig config;

	KeriServerBind() {
		Map<ChannelOption<?>, Boolean> childOptions = new HashMap<>(2);
		childOptions.put(ChannelOption.AUTO_READ, false);
		childOptions.put(ChannelOption.TCP_NODELAY, true);
		this.config = new KeriServerConfig(
				Collections.singletonMap(ChannelOption.SO_REUSEADDR, true),
				childOptions,
				() -> new InetSocketAddress(DEFAULT_PORT));
	}

	KeriServerBind(KeriServerConfig config) {
		this.config = config;
	}

	@Override
	public KeriServerConfig configuration() {
		return config;
	}

	@Override
	protected KeriServer duplicate() {
		return new KeriServerBind(new KeriServerConfig(config));
	}
}
