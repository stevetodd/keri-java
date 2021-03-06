package foundation.identity.keri.transport.tcp;

import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.controller.KeyEventSerializer;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

import java.util.Map;

import static foundation.identity.keri.QualifiedBase64.attachedSignatureCode;
import static foundation.identity.keri.QualifiedBase64.base64;
import static java.nio.charset.StandardCharsets.UTF_8;

public class AttachmentEventEncoder extends MessageToByteEncoder<AttachmentEvent> {

  private static final KeyEventSerializer SERIALIZER = KeyEventSerializer.INSTANCE;

  @Override
  protected void encode(ChannelHandlerContext ctx, AttachmentEvent event, ByteBuf out) {
    out.writeBytes(SERIALIZER.serialize(event));

    // TODO: still a hack
    var signatures = event.receipts()
        .values()
        .stream()
        .findFirst()
        .get();

    out.writeCharSequence("-A", UTF_8);
    out.writeCharSequence(base64(signatures.size(), 2), UTF_8);

    signatures
        .entrySet()
        .stream()
        .sorted(Map.Entry.comparingByKey())
        .forEachOrdered(kv -> {
          var index = kv.getKey();
          var signature = kv.getValue();
          out.writeCharSequence(attachedSignatureCode(signature.algorithm(), index), UTF_8);
          out.writeCharSequence(base64(signature.bytes()), UTF_8);
        });
  }

}
