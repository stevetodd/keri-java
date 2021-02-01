package foundation.identity.keri.demo;

import foundation.identity.keri.api.crypto.StandardSignatureAlgorithms;
import foundation.identity.keri.api.event.IdentifierEvent;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.MessageToByteEncoder;

import java.util.Comparator;

import static foundation.identity.keri.QualifiedBase64.base64;
import static java.nio.charset.StandardCharsets.UTF_8;

public class NettyKERIClient {

  private final String host;
  private final int port;

  public NettyKERIClient(String host, int port) {
    this.host = host;
    this.port = port;
  }

  public void connect() throws InterruptedException {
    EventLoopGroup workerGroup = new NioEventLoopGroup();
    try {
      Bootstrap b = new Bootstrap();
      b.group(workerGroup);
      b.channel(NioSocketChannel.class);
      b.option(ChannelOption.SO_KEEPALIVE, true);
      b.handler(new ChannelInitializer<SocketChannel>() {
        @Override
        public void initChannel(SocketChannel ch) throws Exception {
          ch.pipeline().addLast(new MessageEncoder());
        }
      });

      // Start the client.
      ChannelFuture f = b.connect(host, port).sync();

      // Wait until the connection is closed.
      f.channel().closeFuture().sync();
    } finally {
      workerGroup.shutdownGracefully();
    }
  }

  public void sendMessage() {

  }

  public static class MessageEncoder extends MessageToByteEncoder<IdentifierEvent> {

    @Override
    protected void encode(ChannelHandlerContext ctx, IdentifierEvent msg, ByteBuf out) throws Exception {
      out.writeBytes(msg.bytes());

      out.writeCharSequence("-A", UTF_8);
      out.writeCharSequence(base64(msg.signatures().size()), UTF_8);

      msg.signatures().stream().sorted(Comparator.comparingInt(s -> s.key().index()))
          .forEachOrdered(es -> {
            var stdAlgo = StandardSignatureAlgorithms.valueOf(es.signature().algorithm());
            switch (stdAlgo) {
              case ED_25519 -> {
                out.writeCharSequence("A", UTF_8);
                out.writeCharSequence(base64(es.key().index(), 1), UTF_8);
                out.writeCharSequence(base64(es.signature().bytes()), UTF_8);
              }
              case EC_SECP256K1 -> {
                out.writeCharSequence("B", UTF_8);
                out.writeCharSequence(base64(es.key().index(), 1), UTF_8);
                out.writeCharSequence(base64(es.signature().bytes()), UTF_8);
              }
              case ED_448 -> {
                out.writeCharSequence("0A", UTF_8);
                out.writeCharSequence(base64(es.key().index(), 2), UTF_8);
                out.writeCharSequence(base64(es.signature().bytes()), UTF_8);
              }
            }
          });
    }

  }

}
