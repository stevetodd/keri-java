package foundation.identity.keri.demo;

import foundation.identity.keri.api.event.IdentifierEvent;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;

import java.net.SocketAddress;
import java.util.concurrent.Flow.Subscriber;
import java.util.concurrent.SubmissionPublisher;

public class NettyKERIServer implements java.util.concurrent.Flow.Publisher<IdentifierEvent> {

  EventLoopGroup bossGroup = new NioEventLoopGroup();
  EventLoopGroup workerGroup = new NioEventLoopGroup();
  SubmissionPublisher<IdentifierEvent> publisher = new SubmissionPublisher<>();

  Channel listeningChannel;

  public ChannelFuture bind(SocketAddress address) {
    try {
      ServerBootstrap b = new ServerBootstrap();
      b.group(bossGroup, workerGroup)
          .localAddress(address)
          .channel(NioServerSocketChannel.class)
          .option(ChannelOption.SO_BACKLOG, 128)
          .childOption(ChannelOption.AUTO_READ, false)
          .childOption(ChannelOption.SO_KEEPALIVE, true)
          .childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            public void initChannel(SocketChannel ch) {
              ch.pipeline().addLast(
                  new LoggingHandler(LogLevel.INFO),
                  new KeriMessageDecoder(),
                  new LoggingHandler(LogLevel.INFO),
                  new SubmitterHandler(NettyKERIServer.this.publisher));
            }
          });

      // Bind and start to accept incoming connections.
      ChannelFuture f = b.bind();
      this.listeningChannel = f.channel();
      return f;
    } finally {
    }
  }

  public ChannelFuture shutdown() {
    workerGroup.shutdownGracefully();
    bossGroup.shutdownGracefully();
    return this.listeningChannel.close();
  }

  @Override
  public void subscribe(Subscriber<? super IdentifierEvent> subscriber) {
    this.publisher.subscribe(subscriber);
  }

  private static class SubmitterHandler extends ChannelInboundHandlerAdapter {

    final SubmissionPublisher<IdentifierEvent> publisher;

    public SubmitterHandler(SubmissionPublisher<IdentifierEvent> publisher) {
      this.publisher = publisher;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
      publisher.submit((IdentifierEvent) msg);
    }

  }


}
