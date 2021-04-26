package foundation.identity.keri.transport.tcp;

import foundation.identity.keri.api.event.KeyEvent;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

import java.util.Map;

import static foundation.identity.keri.QualifiedBase64.attachedSignatureCode;
import static foundation.identity.keri.QualifiedBase64.base64;
import static java.nio.charset.StandardCharsets.UTF_8;

public class KeyEventEncoder extends MessageToByteEncoder<KeyEvent> {

  @Override
  protected void encode(ChannelHandlerContext ctx, KeyEvent event, ByteBuf out) {
    out.writeBytes(event.bytes());

    // this will be replaced when we support new framing. For now, direct mode
    var eventSignature = event.signatures();

    out.writeCharSequence("-A", UTF_8);
    out.writeCharSequence(base64(event.signatures().size(), 2), UTF_8);

    event.signatures()
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
