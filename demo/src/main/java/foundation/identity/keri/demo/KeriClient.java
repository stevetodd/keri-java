package foundation.identity.keri.demo;

import foundation.identity.keri.api.event.Event;
import io.netty.channel.ChannelOption;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;
import reactor.netty.tcp.TcpClient;

import java.io.Closeable;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

public class KeriClient implements Closeable {

  private final Connection connection;

  KeriClient(Connection connection) {
    this.connection = connection;
  }

  public static Mono<KeriClient> connect(InetSocketAddress address) {
    return TcpClient.create()
        .metrics(true)
        //.wiretap("keri-client", LogLevel.INFO, AdvancedByteBufFormat.TEXTUAL)
        .remoteAddress(() -> address)
        .option(ChannelOption.SO_KEEPALIVE, true)
        .doOnChannelInit((connectionObserver, channel, remoteAddress) -> {
          channel.pipeline()
              .addLast(new KeriMessageEncoder())
              .addLast(new KeriMessageDecoder());
        })
        .connect()
        // there should be no inbound data for clients
        .doOnSuccess(conn -> conn.inbound().receive().subscribe())
        .map(KeriClient::new);
  }

  public void close() {
    this.connection.dispose();
  }

  public Mono<Void> onClose() {
    return this.connection.onDispose();
  }

  public SocketAddress remoteAddress() {
    return this.connection.channel().remoteAddress();
  }

  public KeriClient send(Publisher<? extends Event> events) {
    connection
        .outbound()
        .sendObject(Flux.from(events))
        .then()
        .subscribe();
    return this;
  }

  // public Flux<Event> receive() {
  //   return connection.inbound()
  //       .receiveObject()
  //       .cast(Event.class);
  // }
}
