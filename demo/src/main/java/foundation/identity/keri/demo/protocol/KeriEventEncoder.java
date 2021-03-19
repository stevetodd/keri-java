package foundation.identity.keri.demo.protocol;

import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.ReceiptFromBasicIdentifierEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferableIdentifierEvent;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

import java.util.Collection;

import static foundation.identity.keri.QualifiedBase64.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Comparator.comparingInt;

public class KeriEventEncoder extends MessageToByteEncoder<Event> {

  @Override
  protected void encode(ChannelHandlerContext ctx, Event event, ByteBuf out) {
    writeEvent(out, event);
    if (event instanceof IdentifierEvent) {
      writeSignatures(out, ((IdentifierEvent) event).signatures());
    } else if (event instanceof ReceiptFromTransferableIdentifierEvent) {
      var r = (ReceiptFromTransferableIdentifierEvent) event;
      writeSignatures(out, r.signatures());
    } else if (event instanceof ReceiptFromBasicIdentifierEvent) {
      var r = (ReceiptFromBasicIdentifierEvent) event;
      writeReceipts(out, r.receipts());
    }
  }

  static void writeEvent(ByteBuf out, Event event) {
    out.writeBytes(event.bytes());
  }

  static void writeSignatures(ByteBuf out, Collection<AttachedEventSignature> signatures) {
    out.writeCharSequence("-A", UTF_8);
    out.writeCharSequence(base64(signatures.size(), 2), UTF_8);

    signatures.stream()
        .sorted(comparingInt(AttachedEventSignature::keyIndex))
        .forEachOrdered(s -> writeSignature(out, s));
  }

  static void writeSignature(ByteBuf out, AttachedEventSignature signature) {
    out.writeCharSequence(
        attachedSignatureCode(signature.signature().algorithm(), signature.keyIndex()), UTF_8);
    out.writeCharSequence(base64(signature.signature().bytes()), UTF_8);
  }

  static void writeReceipts(ByteBuf out, Collection<EventSignature> receipts) {
    out.writeCharSequence("-A", UTF_8);
    out.writeCharSequence(base64(receipts.size(), 2), UTF_8);

    receipts.stream()
        .sequential()
        .forEachOrdered(r -> writeReceipt(out, r));
  }

  static void writeReceipt(ByteBuf out, EventSignature receipt) {
    out.writeCharSequence(qb64(receipt.key().establishmentEvent().identifier()), UTF_8);
    out.writeCharSequence(qb64(receipt.signature()), UTF_8);
  }

}
