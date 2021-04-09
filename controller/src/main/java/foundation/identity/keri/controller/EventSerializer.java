package foundation.identity.keri.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import foundation.identity.keri.QualifiedBase64;
import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.crypto.StandardFormats;
import foundation.identity.keri.api.crypto.StandardSignatureAlgorithms;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.event.SigningThreshold.Weighted.Weight;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.identifier.SelfAddressingIdentifier;
import foundation.identity.keri.api.identifier.SelfSigningIdentifier;
import foundation.identity.keri.api.seal.DigestSeal;
import foundation.identity.keri.api.seal.KeyEventCoordinatesSeal;
import foundation.identity.keri.api.seal.MerkleTreeRootSeal;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.controller.spec.IdentifierSpec;
import foundation.identity.keri.controller.spec.InteractionSpec;
import foundation.identity.keri.controller.spec.ReceiptFromTransferableIdentifierSpec;
import foundation.identity.keri.controller.spec.ReceiptSpec;
import foundation.identity.keri.controller.spec.RotationSpec;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static foundation.identity.keri.Hex.hexNoPad;
import static foundation.identity.keri.QualifiedBase64.qb64;
import static foundation.identity.keri.api.event.EventFieldNames.*;
import static java.nio.charset.StandardCharsets.UTF_8;

public final class EventSerializer {
  private static final byte[] KERI_BYTES = "KERI".getBytes(UTF_8);

  private static final String INCEPTION_TYPE = "icp";
  private static final String ROTATION_TYPE = "rot";
  private static final String INTERACTION_TYPE = "ixn";
  private static final String DELEGATED_INCEPTION_TYPE = "dip";
  private static final String DELEGATED_ROTATION_TYPE = "drt";
  private static final String RECEIPT_FROM_BASIC_TYPE = "rct";
  private static final String RECEIPT_FROM_TRANSFERABLE_TYPE = "vrc";

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());
  private static final ObjectMapper MESSAGE_PACK = new ObjectMapper(new MessagePackFactory());

  static String identifierPlaceholder(IdentifierSpec spec) {
    var derivation = spec.derivation();
    if (derivation.isAssignableFrom(BasicIdentifier.class)) {
      var publicKey = spec.keys().get(0);
      var signatureAlgorithm = StandardSignatureAlgorithms.lookup(publicKey);
      return QualifiedBase64.basicIdentifierPlaceholder(signatureAlgorithm);
    } else if (derivation.isAssignableFrom(SelfAddressingIdentifier.class)) {
      var digestAlgorithm = spec.selfAddressingDigestAlgorithm();
      return QualifiedBase64.selfAddressingIdentifierPlaceholder(digestAlgorithm);
    } else if (derivation.isAssignableFrom(SelfSigningIdentifier.class)) {
      return QualifiedBase64.selfSigningIdentifierPlaceholder(spec.signer().algorithm());
    } else {
      throw new IllegalArgumentException("unknown prefix type: " + derivation.getCanonicalName());
    }
  }

  static String version(Version v, Format f, long size) {
    return String.format("KERI%x%x%s%06x_", v.major(), v.minor(), format(f), size);
  }

  static String format(Format f) {
    return switch (StandardFormats.lookup(f.formatName())) {
      case CBOR -> "CBOR";
      case JSON -> "JSON";
      case MESSAGE_PACK -> "MGPK";
    };
  }

  static ObjectNode seal(Seal seal, ObjectMapper mapper) {
    var obj = mapper.createObjectNode();
    if (seal instanceof KeyEventCoordinatesSeal) {
      var els = (KeyEventCoordinatesSeal) seal;
      obj.put("i", qb64(els.event().identifier()));
      obj.put("s", hexNoPad(els.event().sequenceNumber()));
      obj.put("d", qb64(els.event().digest()));
    } else if ((seal instanceof DigestSeal)) {
      obj.put("d", qb64(((DigestSeal) seal).digest()));
    } else if (seal instanceof MerkleTreeRootSeal) {
      obj.put("rd", qb64(((MerkleTreeRootSeal) seal).digest()));
    } else {
      throw new IllegalArgumentException("Unknown seal type: " + seal.getClass());
    }
    return obj;
  }

  static JsonNode signingThreshold(SigningThreshold t, ObjectMapper mapper) {
    if (t instanceof SigningThreshold.Unweighted) {
      return mapper.getNodeFactory().textNode(((SigningThreshold.Unweighted) t).threshold() + "");
    } else if (t instanceof SigningThreshold.Weighted) {
      var wt = (SigningThreshold.Weighted) t;
      var groupArrayNodes = Stream.of(wt.weights())
          .map(lw -> {
                var textNodes = Stream.of(lw)
                    .map(EventSerializer::weight)
                    .map(str -> mapper.getNodeFactory().textNode(str))
                    .collect(Collectors.toList());
                return mapper.getNodeFactory().arrayNode()
                    .addAll(textNodes);
          })
          .collect(Collectors.toList());

      return mapper.getNodeFactory().arrayNode()
          .addAll(groupArrayNodes);
    } else {
      throw new IllegalArgumentException("Unknown SigningThreshold type: " + t.getClass());
    }
  }

  static String weight(Weight w) {
    if (w.denominator().isEmpty()) {
      return "" + w.numerator();
    }

    return w.numerator() + "/" + w.denominator().get();
  }

  static void writeSize(byte[] bytes) {
    // version string is "KERIVVFFFFSSSSSS_"
    // VV = version
    // FFFF = format
    // SSSSSS = size in hex
    var sizeStart = indexOf(bytes, KERI_BYTES, 10) + 10;
    var sizeStringBytes = String.format("%06x", bytes.length).getBytes(UTF_8);

    bytes[sizeStart] = sizeStringBytes[0];
    bytes[sizeStart + 1] = sizeStringBytes[1];
    bytes[sizeStart + 2] = sizeStringBytes[2];
    bytes[sizeStart + 3] = sizeStringBytes[3];
    bytes[sizeStart + 4] = sizeStringBytes[4];
    bytes[sizeStart + 5] = sizeStringBytes[5];
  }

  static int indexOf(byte[] a, byte[] b, int limit) {
    for (var i = 0; (i < a.length) && (i < limit) && ((i + b.length) <= a.length); i++) {
      if (Arrays.equals(a, i, i + b.length, b, 0, b.length)) {
        return i;
      }
    }
    return -1;
  }

  private ObjectMapper mapper(Format format) {
    var stdFormat = (StandardFormats) format;
    return switch (stdFormat) {
      case CBOR -> CBOR;
      case JSON -> JSON;
      case MESSAGE_PACK -> MESSAGE_PACK;
    };
  }

  public byte[] inceptionStatement(IdentifierSpec spec) {
    return serialize(null, spec);
  }

  public byte[] serialize(Identifier identifier, IdentifierSpec spec) {
    var mapper = mapper(spec.format());
    var rootNode = mapper.createObjectNode();

    rootNode.put(VERSION.label(), version(Version.CURRENT, spec.format(), 0));
    if (identifier == null) {
      rootNode.put(IDENTIFIER.label(), identifierPlaceholder(spec));
    } else {
      rootNode.put(IDENTIFIER.label(), qb64(identifier));
    }
    rootNode.put(SEQUENCE_NUMBER.label(), hexNoPad(0));
    rootNode.put(EVENT_TYPE.label(), INCEPTION_TYPE);

    rootNode.set(SIGNING_THRESHOLD.label(), signingThreshold(spec.signingThreshold(), mapper));

    var keysNode = mapper.createArrayNode();
    spec.keys().forEach(k -> keysNode.add(qb64(k)));
    rootNode.set(KEYS.label(), keysNode);

    if (KeyConfigurationDigest.NONE.equals(spec.nextKeys())) {
      rootNode.put(NEXT_KEYS_DIGEST.label(), "");
    } else {
      rootNode.put(NEXT_KEYS_DIGEST.label(), qb64(spec.nextKeys()));
    }

    rootNode.put(WITNESS_THRESHOLD.label(), hexNoPad(spec.witnessThreshold()));
    var witnessesNode = mapper.createArrayNode();
    if (!spec.witnesses().isEmpty()) {
      spec.witnesses().forEach(w -> witnessesNode.add(qb64(w)));
    }
    rootNode.set(WITNESSES.label(), witnessesNode);

    rootNode.set(CONFIGURATION.label(), mapper.createArrayNode()); // TODO


    try {
      var bytes = mapper.writeValueAsBytes(rootNode);
      writeSize(bytes);
      return bytes;
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  public byte[] serialize(RotationSpec spec) {
    var mapper = mapper(spec.format());
    var rootNode = mapper.createObjectNode();

    rootNode.put(VERSION.label(), version(Version.CURRENT, spec.format(), 0));
    rootNode.put(IDENTIFIER.label(), qb64(spec.identifier()));
    rootNode.put(SEQUENCE_NUMBER.label(), hexNoPad(spec.sequenceNumber()));
    rootNode.put(EVENT_TYPE.label(), ROTATION_TYPE);
    rootNode.put(PRIOR_EVENT_DIGEST.label(), qb64(spec.previous().digest()));

    rootNode.set(SIGNING_THRESHOLD.label(), signingThreshold(spec.signingThreshold(), mapper));

    var keysNode = mapper.createArrayNode();
    spec.keys().forEach(k -> keysNode.add(qb64(k)));
    rootNode.set(KEYS.label(), keysNode);

    if (KeyConfigurationDigest.NONE.equals(spec.nextKeys())) {
      rootNode.put(NEXT_KEYS_DIGEST.label(), "");
    } else {
      rootNode.put(NEXT_KEYS_DIGEST.label(), qb64(spec.nextKeys()));
    }

    rootNode.put(WITNESS_THRESHOLD.label(), hexNoPad(spec.witnessThreshold()));

    var removedWitnessesNode = mapper.createArrayNode();
    spec.removedWitnesses().forEach(w -> removedWitnessesNode.add(qb64(w)));
    rootNode.set(WITNESSES_REMOVED.label(), removedWitnessesNode);

    var addedWitnessesNode = mapper.createArrayNode();
    spec.addedWitnesses().forEach(w -> addedWitnessesNode.add(qb64(w)));
    rootNode.set(WITNESSES_ADDED.label(), addedWitnessesNode);

    var sealsNode = mapper.createArrayNode();
    spec.seals().forEach(s -> sealsNode.add(seal(s, mapper)));
    rootNode.set(ANCHORS.label(), sealsNode);

    try {
      var bytes = mapper.writeValueAsBytes(rootNode);
      writeSize(bytes);
      return bytes;
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  public byte[] serialize(InteractionSpec spec) {
    var mapper = mapper(spec.format());
    var rootNode = mapper.createObjectNode();

    rootNode.put(VERSION.label(), version(Version.CURRENT, spec.format(), 0));
    rootNode.put(IDENTIFIER.label(), qb64(spec.identifier()));
    rootNode.put(SEQUENCE_NUMBER.label(), hexNoPad(spec.sequenceNumber()));
    rootNode.put(EVENT_TYPE.label(), INTERACTION_TYPE);
    rootNode.put(PRIOR_EVENT_DIGEST.label(), qb64(spec.previous().digest()));

    var sealsNode = mapper.createArrayNode();
    spec.seals().forEach(s -> sealsNode.add(seal(s, mapper)));
    rootNode.set(ANCHORS.label(), sealsNode);

    try {
      var bytes = mapper.writeValueAsBytes(rootNode);
      writeSize(bytes);
      return bytes;
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  public byte[] serialize(ReceiptFromTransferableIdentifierSpec spec) {
    var mapper = mapper(spec.format());
    var rootNode = mapper.createObjectNode();

    rootNode.put(VERSION.label(), version(Version.CURRENT, spec.format(), 0));
    rootNode.put(IDENTIFIER.label(), qb64(spec.event().identifier()));
    rootNode.put(SEQUENCE_NUMBER.label(), hexNoPad(spec.event().sequenceNumber()));
    rootNode.put(EVENT_TYPE.label(), RECEIPT_FROM_TRANSFERABLE_TYPE);
    rootNode.put(EVENT_DIGEST.label(), qb64(spec.event().digest()));

    var eventSignature = spec.signatures()
        .stream()
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("at least one signature is required"));
    var anchorNode = mapper.createObjectNode();
    anchorNode.put(IDENTIFIER.label(), qb64(eventSignature.key().establishmentEvent().identifier()));
    anchorNode.put(SEQUENCE_NUMBER.label(), hexNoPad(eventSignature.key().establishmentEvent().sequenceNumber()));
    anchorNode.put(EVENT_DIGEST.label(), qb64(eventSignature.key().establishmentEvent().digest()));
    rootNode.set(ANCHORS.label(), anchorNode);

    try {
      var bytes = mapper.writeValueAsBytes(rootNode);
      writeSize(bytes);
      return bytes;
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  public byte[] serialize(ReceiptSpec spec) {
    var mapper = mapper(spec.format());
    var rootNode = mapper.createObjectNode();

    rootNode.put(VERSION.label(), version(Version.CURRENT, spec.format(), 0));
    rootNode.put(IDENTIFIER.label(), qb64(spec.event().identifier()));
    rootNode.put(SEQUENCE_NUMBER.label(), hexNoPad(spec.event().sequenceNumber()));
    rootNode.put(EVENT_TYPE.label(), RECEIPT_FROM_BASIC_TYPE);
    rootNode.put(EVENT_DIGEST.label(), qb64(spec.event().digest()));

    try {
      var bytes = mapper.writeValueAsBytes(rootNode);
      writeSize(bytes);
      return bytes;
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

}
