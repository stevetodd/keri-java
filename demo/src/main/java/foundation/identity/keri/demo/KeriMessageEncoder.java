package foundation.identity.keri.demo;

import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.ReceiptEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferrableIdentifierEvent;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;

import static foundation.identity.keri.QualifiedBase64.*;
import static java.nio.charset.StandardCharsets.UTF_8;

public class KeriMessageEncoder extends MessageToByteEncoder<Event> {

  static void writeEvent(ByteBuf out, Event event) {
    out.writeBytes(event.bytes());
  }

  static void writeSignatures(ByteBuf out, Collection<EventSignature> eventSignatures) {
    out.writeCharSequence("-A", UTF_8);
    out.writeCharSequence(base64(eventSignatures.size(), 2), UTF_8);

    eventSignatures.stream().sorted(Comparator.comparingInt(s -> s.key().index()))
        .forEachOrdered(s -> writeSignature(out, s));
  }

  static void writeSignature(ByteBuf out, EventSignature eventSignature) {
    out.writeCharSequence(
        attachedSignatureCode(eventSignature.signature().algorithm(), eventSignature.key().index()), UTF_8);
    out.writeCharSequence(base64(eventSignature.signature().bytes()), UTF_8);
  }

  static void writeReceipts(ByteBuf out, Collection<EventSignature> receipts) {
    out.writeCharSequence("-A", UTF_8);
    out.writeCharSequence(base64(receipts.size(), 2), UTF_8);

    receipts.stream().sequential().forEachOrdered(r -> writeReceipt(out, r));
  }

  static void writeReceipt(ByteBuf out, EventSignature receipt) {
    out.writeCharSequence(qb64(receipt.key().identifier()), UTF_8);
    out.writeCharSequence(qb64(receipt.signature()), UTF_8);
  }

  @Override
  protected void encode(ChannelHandlerContext ctx, Event event, ByteBuf out) {
    writeEvent(out, event);
    if (event instanceof IdentifierEvent) {
      writeSignatures(out, ((IdentifierEvent) event).signatures());
    } else if (event instanceof ReceiptFromTransferrableIdentifierEvent) {
      var r = (ReceiptFromTransferrableIdentifierEvent) event;
      writeSignatures(out, List.of(r.receipt()));
    } else if (event instanceof ReceiptEvent) {
      var r = (ReceiptEvent) event;
      writeReceipts(out, r.receipts());
    }
  }

}
