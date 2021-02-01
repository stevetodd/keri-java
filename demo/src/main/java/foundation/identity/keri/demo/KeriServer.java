package foundation.identity.keri.demo;

import foundation.identity.keri.api.event.Event;
import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;
import reactor.netty.DisposableServer;
import reactor.netty.NettyInbound;
import reactor.netty.NettyOutbound;
import reactor.netty.tcp.TcpServer;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

public final class KeriServer {

  final DisposableServer tcpServer;

  KeriServer(DisposableServer tcpServer) {
    this.tcpServer = tcpServer;
  }

  public static Mono<KeriServer> bind(InetSocketAddress socketAddress, Function<KeriServerConnection, Mono<Void>> connectionHandler) {
    System.setProperty("jdk.sunec.disableNative", "false");
    return TcpServer.create()
        //.metrics(true)
        //.wiretap("keri-server", LogLevel.INFO, AdvancedByteBufFormat.TEXTUAL)
        .childOption(ChannelOption.SO_KEEPALIVE, true)
        .doOnConnection(conn -> {
          conn.addHandler(new ReadTimeoutHandler(10, TimeUnit.SECONDS));
          conn.addHandlerLast(new KeriMessageEncoder());
          conn.addHandlerLast(new KeriMessageDecoder());
        })
        .bindAddress(() -> socketAddress)
        //.handle(handler(handler.get()))
        //.handle(wrapHandler(handler))
        .handle(wrap(connectionHandler))
        .bind()
        .map(KeriServer::new);
  }

  private static BiFunction<? super NettyInbound, ? super NettyOutbound, ? extends Publisher<Void>> wrap(Function<KeriServerConnection, Mono<Void>> connectionHandler) {
    return (in, out) -> {
      var keriConnection = new KeriServerConnection((Connection) in);
      return connectionHandler.apply(keriConnection);
    };
  }

  private static BiFunction<? super NettyInbound, ? super NettyOutbound, ? extends Publisher<Void>> wrapHandler(Supplier<EventHandler> handlerSupplier) {
    return (in, out) -> {
      var handler = handlerSupplier.get();

      // FIXME
      in.receiveObject()
          .cast(Event.class)
          .subscribe(
              o -> handler.handle(o),
              e -> e.printStackTrace(),
              () -> System.out.println("done"));

      return out.neverComplete();
    };
  }

  public void dispose() {
    this.tcpServer.dispose();
  }

  public Mono<Void> onDispose() {
    return this.tcpServer.onDispose();
  }

  public static class KeriServerConnection {

    private final Connection connection;

    public KeriServerConnection(Connection connection) {
      this.connection = connection;
    }

    public void close() {
      this.connection.dispose();
    }

    public Mono<Void> onClose() {
      return this.connection.onDispose();
    }

    public Mono<Void> send(Publisher<Event> events) {
      return connection
          .outbound()
          .sendObject(Flux.from(events))
          .then();
    }

    public Flux<Event> receive() {
      return connection.inbound()
          .receiveObject()
          .cast(Event.class);
    }

    public SocketAddress remoteAddress() {
      return connection.channel().remoteAddress();
    }

  }

}
