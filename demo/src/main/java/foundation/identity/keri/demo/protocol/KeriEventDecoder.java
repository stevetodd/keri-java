package foundation.identity.keri.demo.protocol;

import foundation.identity.keri.EventDeserializer;
import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.crypto.SignatureAlgorithm;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.crypto.SignatureOperations;
import foundation.identity.keri.internal.identifier.ImmutableBasicIdentifier;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ReplayingDecoder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static foundation.identity.keri.Hex.unhexInt;
import static foundation.identity.keri.QualifiedBase64.*;
import static java.nio.charset.StandardCharsets.UTF_8;

public class KeriEventDecoder extends ReplayingDecoder<Void> {

  private static final ByteBuf KERI = Unpooled.wrappedBuffer("KERI".getBytes(UTF_8));
  private static final int MAX_PEEK = 10;
  private static final int VERSION_STRING_LENGTH = "KERIVVFFFSSSSSS_".length();

  private final EventDeserializer deserializer = new EventDeserializer();

  @Override
  protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
    var messageBytes = readMessage(in);
    var signatures = readSignatures(in);
    // var receipts = readReceipts(in); // Pending keri#91

    var event = this.deserializer.deserialize(messageBytes, signatures);

    out.add(event);
  }

  static byte[] readMessage(ByteBuf in) {
    var length = peekMessageLength(in);

    if (length == 0) {
      throw new IllegalArgumentException("couldn't read size from message");
    }

    var bytes = new byte[length];
    in.readBytes(bytes);
    return bytes;
  }

  static int peekMessageLength(ByteBuf in) {
    var versionStart = ByteBufUtil.indexOf(KERI, in);

    if (versionStart == -1) {
      if (in.readableBytes() > (MAX_PEEK + VERSION_STRING_LENGTH)) {
        throw new IllegalStateException("couldn't find version in message");
      } else {
        // need to read more
        throw new IndexOutOfBoundsException();
      }
    }

    var sizeBytes = new byte[6];
    in.getBytes(versionStart + 10, sizeBytes);
    var sizeHex = new String(sizeBytes, UTF_8);
    return unhexInt(sizeHex);
  }

  static Map<Integer, Signature> readSignatures(ByteBuf in) {
    var isBase64 = readMode(in);
    var count = readBase64Int(in, 2);

    var signatures = new HashMap<Integer, Signature>(count);
    for (var i = 0; i < count; i++) {
      var code = readQmCode(in);
      var index = readSignatureIndex(in, code);
      var algorithm = attachedSignatureAlgorithm(code);
      var signature = readSignature(in, algorithm, isBase64);
      signatures.put(index, signature);
    }

    return signatures;
  }

  static int readSignatureIndex(ByteBuf in, String code) {
    return switch (code.length()) {
      case 1 -> readBase64Int(in, 1);
      case 2 -> readBase64Int(in, 2);
      default -> throw new IllegalArgumentException("invalid code: " + code);
    };
  }

  static boolean readMode(ByteBuf in) {
    var mode = readString(in, 2);

    if (mode.charAt(0) != '-') {
      throw new IllegalArgumentException("unknown mode: " + mode);
    }

    return switch (mode.charAt(1)) {
      case 'A' -> true;
      case 'B' -> false;
      default -> throw new IllegalArgumentException("unknown mode: " + mode);
    };
  }

  static Signature readSignature(ByteBuf in, SignatureAlgorithm algorithm, boolean isBase64) {
    byte[] bytes;

    if (isBase64) {
      bytes = readBase64(in, algorithm.signatureLength());
    } else {
      bytes = new byte[algorithm.signatureLength()];
      in.readBytes(bytes);
    }

    return SignatureOperations.lookup(algorithm).signature(bytes);
  }

  static Map<BasicIdentifier, Signature> readReceipts(ByteBuf in) {
    var isBase64 = readMode(in);
    var count = readBase64Int(in, 2);

    var signatures = new HashMap<BasicIdentifier, Signature>(count);
    for (var i = 0; i < count; i++) {
      var prefixCode = readQmCode(in);
      var prefixAlgorithm = basicIdentifierSignatureAlgorithm(prefixCode);
      var prefix = readBasicIdentifier(in, prefixAlgorithm, isBase64);

      var signatureCode = readQmCode(in);
      var signatureAlgorithm = signatureAlgorithm(signatureCode);
      var signature = readSignature(in, signatureAlgorithm, isBase64);

      signatures.put(prefix, signature);
    }

    return signatures;
  }

  static BasicIdentifier readBasicIdentifier(ByteBuf in, SignatureAlgorithm algorithm, boolean isBase64) {
    byte[] bytes;

    if (isBase64) {
      bytes = readBase64(in, algorithm.publicKeyLength());
    } else {
      bytes = new byte[algorithm.publicKeyLength()];
      in.readBytes(bytes);
    }

    var publicKey = SignatureOperations.lookup(algorithm).publicKey(bytes);

    return new ImmutableBasicIdentifier(publicKey);
  }

  // reads base64 bytes to fill an array of length bytesLength
  static byte[] readBase64(ByteBuf in, int bytesLength) {
    var length = base64Length(bytesLength);
    return unbase64(readString(in, length));
  }

  static int readBase64Int(ByteBuf in, int length) {
    return unbase64Int(readString(in, length));
  }

  static String readString(ByteBuf in, int length) {
    return in.readBytes(length).toString(UTF_8);
  }

  static String readQmCode(ByteBuf in) {
    return switch (in.getChar(in.readerIndex())) {
      case '0' -> readString(in, 2);
      case '1' -> readString(in, 4);
      default -> readString(in, 1);
    };
  }

}
