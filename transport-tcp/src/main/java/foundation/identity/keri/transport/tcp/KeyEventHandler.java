package foundation.identity.keri.transport.tcp;

import foundation.identity.keri.AttachmentEventProcessingException;
import foundation.identity.keri.KeyEventProcessingException;
import foundation.identity.keri.KeyEventProcessor;
import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.controller.ControllableIdentifier;
import foundation.identity.keri.internal.event.ImmutableAttachmentEvent;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Map;

import static foundation.identity.keri.ShortQualifiedBase64.shortQb64;

class KeyEventHandler extends ChannelInboundHandlerAdapter {
  private static final Logger LOGGER = LoggerFactory.getLogger(KeyEventHandler.class);

  private final ControllableIdentifier controller;
  private final KeyEventProcessor processor;

  private final ArrayList<KeyEvent> acceptedEvents = new ArrayList<>();

  public KeyEventHandler(ControllableIdentifier controller, KeyEventProcessor processor) {
    this.controller = controller;
    this.processor = processor;
  }

  @Override
  public void channelActive(ChannelHandlerContext ctx) throws Exception {
    super.channelActive(ctx);
    ctx.read();
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) {
    if (msg instanceof KeyEvent) {
      this.readKeyEvent(ctx, (KeyEvent) msg);
    } else if (msg instanceof AttachmentEvent) {
      this.readAttachmentEvent(ctx, (AttachmentEvent) msg);
    }
  }

  @Override
  public void channelReadComplete(ChannelHandlerContext ctx) {
    LOGGER.debug("READ COMPLETE");

    for (var e : this.acceptedEvents) {
      this.sendOwnLogIfNecessary(ctx, e);
      LOGGER.debug("SENDING RECEIPT FOR: {}", shortQb64(e.coordinates()));
      ctx.writeAndFlush(this.buildReceipt(e))
          .addListener(f -> ctx.read());
    }

    this.acceptedEvents.clear();
  }

  private void readKeyEvent(ChannelHandlerContext ctx, KeyEvent keyEvent) {
    try {
      LOGGER.debug("PROCESS: {}", shortQb64(keyEvent.coordinates()));
      this.processor.process(keyEvent);

      LOGGER.debug("ACCEPTED");
      this.acceptedEvents.add(keyEvent);

      ctx.read();
    } catch (KeyEventProcessingException e) {
      LOGGER.debug("REJECTED: ({}) {}",
          e.getClass().getSimpleName(),
          e.getMessage());
      ctx.write(e);
      ctx.read();
    } catch (Exception e) {
      LOGGER.error("Processing could not be completed.", e);
      ctx.writeAndFlush(e)
          .addListener(ChannelFutureListener.CLOSE);
    }
  }

  private void readAttachmentEvent(ChannelHandlerContext ctx, AttachmentEvent attachmentEvent) {
    try {
      LOGGER.debug("PROCESS ATTACHMENT: {}", shortQb64(attachmentEvent.coordinates()));
      this.processor.process(attachmentEvent);
      ctx.read();
    } catch (AttachmentEventProcessingException e) {
      LOGGER.debug("REJECTED: ({}) {}",
          e.getClass().getSimpleName(),
          e.getMessage(),
          e);
      ctx.write(e);
      ctx.read();
    } catch (Exception e) {
      LOGGER.error("Processing could not be completed.", e);
      ctx.writeAndFlush(e)
          .addListener(ChannelFutureListener.CLOSE);
    }
  }

  private void sendOwnLogIfNecessary(ChannelHandlerContext ctx, KeyEvent event) {
    var latestReceipt = this.processor.keyEventStore()
        .findLatestReceipt(this.controller.identifier(), event.identifier())
        .orElse(-1);

    this.processor.keyEventStore()
        .streamKeyEvents(this.controller.identifier(), latestReceipt + 1)
        .peek(ke -> LOGGER.debug("SEND EVENT: {}", shortQb64(ke.coordinates())))
        .forEachOrdered(ctx::write);
  }

  private AttachmentEvent buildReceipt(KeyEvent event) {
    var receipt = this.controller.sign(event);
    return new ImmutableAttachmentEvent(
        event.coordinates(),
        Map.of(),
        Map.of(),
        Map.of(receipt.keyEstablishmentEvent(), receipt.signatures()));
  }

}
