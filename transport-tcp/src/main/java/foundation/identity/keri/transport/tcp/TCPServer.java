package foundation.identity.keri.transport.tcp;

import foundation.identity.keri.KeyEventProcessor;
import foundation.identity.keri.api.event.Event;
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
import io.netty.handler.logging.ByteBufFormat;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;

import java.net.SocketAddress;

public final class TCPServer  {

  private Channel listeningChannel;

  private final EventLoopGroup bossGroup = new NioEventLoopGroup();
  private final EventLoopGroup workerGroup = new NioEventLoopGroup();

  private final KeyEventProcessor processor;

  public TCPServer(KeyEventProcessor processor) {
    this.processor = processor;
  }

  public ChannelFuture bind(SocketAddress address) {
    try {
      var b = new ServerBootstrap();
      b.group(this.bossGroup, this.workerGroup)
          .localAddress(address)
          .channel(NioServerSocketChannel.class)
          //.option(ChannelOption.SO_BACKLOG, 128)
          //.childOption(ChannelOption.AUTO_READ, false)
          .childOption(ChannelOption.SO_KEEPALIVE, true)
          .handler(new LoggingHandler(LogLevel.INFO, ByteBufFormat.SIMPLE))
          .childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            public void initChannel(SocketChannel ch) {
              ch.pipeline().addLast(
                  new KeriEventDecoder(),
                  new KeriEventEncoder(),
                  //new LoggingHandler(LogLevel.INFO, ByteBufFormat.SIMPLE),
                  new EventHandler(TCPServer.this.processor));
            }
          });

      // Bind and start to accept incoming connections.
      ChannelFuture f = b.bind();
      this.listeningChannel = f.channel();
      return f;
    } catch (Exception e) {
      throw e;
    }
  }

  public ChannelFuture shutdown() {
    this.workerGroup.shutdownGracefully();
    this.bossGroup.shutdownGracefully();
    return this.listeningChannel.close();
  }

  private static class EventHandler extends ChannelInboundHandlerAdapter {

    final KeyEventProcessor processor;

    public EventHandler(KeyEventProcessor processor) {
      this.processor = processor;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
      this.processor.process((Event) msg);
    }

  }

}
