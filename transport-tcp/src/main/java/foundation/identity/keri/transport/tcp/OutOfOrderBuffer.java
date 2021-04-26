package foundation.identity.keri.transport.tcp;

import foundation.identity.keri.MissingDelegatingEventException;
import foundation.identity.keri.MissingEventException;
import foundation.identity.keri.MissingReferencedEventException;
import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static foundation.identity.keri.ShortQualifiedBase64.shortQb64;

class OutOfOrderBuffer extends MessageToMessageEncoder<Object> {
  private static final Logger LOGGER = LoggerFactory.getLogger(OutOfOrderBuffer.class);

  private final Map<KeyEventCoordinates, List<KeyEvent>> awaitingEvents = new HashMap<>();
  private final Map<DelegatingEventCoordinates, List<KeyEvent>> awaitingDelegatingEvents = new HashMap<>();
  private final Map<KeyEventCoordinates, List<AttachmentEvent>> attachmentsAwaitingEvents = new HashMap<>();

  @Override
  protected void encode(ChannelHandlerContext ctx, Object msg, List<Object> out) {
    if (msg instanceof KeyEvent) {
      out.add(msg);
    } else if (msg instanceof AttachmentEvent) {
      out.add(msg);
      var r = (AttachmentEvent) msg;
      this.eventsAwaiting(r.coordinates())
          .stream()
          .peek(ke -> LOGGER.debug("UNBUFFER: {}", shortQb64(ke.coordinates())))
          .forEach(ctx::fireChannelRead);
      this.attachmentsAwaiting(r.coordinates())
          .stream()
          .peek(a -> LOGGER.debug("UNBUFFER: {}", shortQb64(a.coordinates())))
          .forEach(ctx::fireChannelRead);
      ctx.fireChannelReadComplete();
      // TODO delegation
    } else if (msg instanceof MissingEventException) {
      var mee = (MissingEventException) msg;
      LOGGER.debug("BUFFER: {} awaits {}", shortQb64(mee.keyEvent().coordinates()), shortQb64(mee.missingEvent()));
      this.await(mee.keyEvent(), mee.missingEvent());
    } else if (msg instanceof MissingDelegatingEventException) {
      var mdee = (MissingDelegatingEventException) msg;
      LOGGER.debug("BUFFER: {} awaits {}", shortQb64(mdee.keyEvent().coordinates()), shortQb64(mdee.missingEvent()));
      this.await(mdee.keyEvent(), mdee.missingEvent());
    } else if (msg instanceof MissingReferencedEventException) {
      var maee = (MissingReferencedEventException) msg;
      LOGGER.debug("BUFFER: RECEIPT {} awaits {}", shortQb64(maee.attachmentEvent().coordinates()), shortQb64(maee.referencedEvent()));
      this.await(maee.attachmentEvent(), maee.referencedEvent());
    }
  }

  private List<KeyEvent> eventsAwaiting(KeyEventCoordinates dependency) {
    return this.nullToEmpty(this.awaitingEvents.remove(dependency));
  }

  private List<KeyEvent> eventsAwaiting(DelegatingEventCoordinates dependency) {
    return this.nullToEmpty(this.awaitingDelegatingEvents.remove(dependency));
  }

  private List<AttachmentEvent> attachmentsAwaiting(KeyEventCoordinates dependency) {
    return this.nullToEmpty(this.attachmentsAwaitingEvents.remove(dependency));
  }

  private void await(KeyEvent event, KeyEventCoordinates dependency) {
    this.awaitingEvents.computeIfAbsent(dependency, k -> new ArrayList<>())
        .add(event);
  }

  private void await(KeyEvent event, DelegatingEventCoordinates dependency) {
    this.awaitingDelegatingEvents.computeIfAbsent(dependency, k -> new ArrayList<>())
        .add(event);
  }

  private void await(AttachmentEvent attachmentEvent, KeyEventCoordinates dependency) {
    this.attachmentsAwaitingEvents.computeIfAbsent(dependency, k -> new ArrayList<>())
        .add(attachmentEvent);
  }

  private <T> List<T> nullToEmpty(List<T> list) {
    return list != null ? list : List.of();
  }

}
