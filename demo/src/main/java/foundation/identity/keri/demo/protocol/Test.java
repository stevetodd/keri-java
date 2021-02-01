package foundation.identity.keri.demo.protocol;

import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;

public class Test {

  public static void main(String[] args) {
    var client = KeriClient.create()
        .remoteAddress(() -> new InetSocketAddress(5620))
        .connectNow();
    var server = KeriServer.create()
        .bindAddress(() -> new InetSocketAddress(5621))
        .handle((in, out) -> {
          var o = client.outbound()
              .send(in.receive())
              .then();
          var i = out.send(client.inbound().receive())
              .then();
          return Mono.zip(o, i).then();
        })
        .bindNow()
        .onDispose()
        .block();

  }

}
