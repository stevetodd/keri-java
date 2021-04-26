package foundation.identity.keri.transport.tcp;

import foundation.identity.keri.KeyEventProcessor;
import foundation.identity.keri.KeyEventStore;
import foundation.identity.keri.controller.ControllableIdentifier;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.DefaultEventLoopGroup;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;

import java.net.SocketAddress;
import java.util.concurrent.Future;

import static java.util.Objects.requireNonNull;

public final class DirectMode {

  private Channel listeningChannel;

  private final static EventLoopGroup acceptorGroup = new NioEventLoopGroup();
  private final static EventLoopGroup connectionsGroup = new NioEventLoopGroup();
  private final static EventLoopGroup eventProcessingGroup = new DefaultEventLoopGroup();

  private final KeyEventStore keyEventStore;
  private final ControllableIdentifier controller;
  private final KeyEventProcessor processor;

  public DirectMode(ControllableIdentifier controller, KeyEventStore keyEventStore) {
    this.controller = requireNonNull(controller);
    this.keyEventStore = requireNonNull(keyEventStore);
    this.processor = new KeyEventProcessor(this.keyEventStore);
  }

  public static ChannelFuture listen(ControllableIdentifier controller, KeyEventStore keyEventStore,
      SocketAddress address) {
    try {
      var processor = new KeyEventProcessor(keyEventStore);
      var b = new ServerBootstrap();
      b.group(acceptorGroup, connectionsGroup)
          .localAddress(address)
          .channel(NioServerSocketChannel.class)
          //.option(ChannelOption.SO_BACKLOG, 128)
          .childOption(ChannelOption.AUTO_READ, false)
          .childOption(ChannelOption.SO_KEEPALIVE, true)
          //.handler(new LoggingHandler(LogLevel.INFO, ByteBufFormat.SIMPLE))
          .childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            public void initChannel(SocketChannel ch) {
              ch.pipeline().addLast(
                  //new LoggingHandler(LogLevel.INFO, ByteBufFormat.HEX_DUMP),
                  new KeyEventDecoder(),
                  new KeyEventEncoder(),
                  new AttachmentEventEncoder(),
                  new OutOfOrderBuffer()
                  );
              ch.pipeline().addLast(
                  eventProcessingGroup,
                  new KeyEventHandler(
                      controller,
                      processor));
            }
          });

      // Bind and start to accept incoming connections.
      return b.bind();
    } catch (Exception e) {
      throw e;
    }
  }

  public static class Server {

    private final ChannelFuture serverChannelFuture;

    protected Server(ChannelFuture serverChannelFuture) {
      this.serverChannelFuture = serverChannelFuture;
    }

    public Future<Void> shutdown() {
      return this.serverChannelFuture.channel().close();
    }

  }

  public static ChannelFuture connect(ControllableIdentifier controller, KeyEventStore keyEventStore,
      SocketAddress address) {
    try {
      var processor = new KeyEventProcessor(keyEventStore);
      var b = new Bootstrap();
      b.group(connectionsGroup)
          .channel(NioSocketChannel.class)
          .option(ChannelOption.AUTO_READ, false)
          .option(ChannelOption.SO_KEEPALIVE, true)
          //.handler(new LoggingHandler(LogLevel.INFO, ByteBufFormat.SIMPLE))
          .handler(new ChannelInitializer<SocketChannel>() {
            @Override
            public void initChannel(SocketChannel ch) {
              ch.pipeline().addLast(
                  //new LoggingHandler(LogLevel.INFO, ByteBufFormat.HEX_DUMP),
                  new KeyEventDecoder(),
                  new KeyEventEncoder(),
                  new AttachmentEventEncoder(),
                  new OutOfOrderBuffer()
              );
              ch.pipeline().addLast(
                  eventProcessingGroup,
                  new KeyEventHandler(
                      controller,
                      processor));
            }
          });

      return b.connect(address);
    } catch (Exception e) {
      throw e;
    }
  }

}
