package foundation.identity.keri;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.DelegatedInceptionEvent;
import foundation.identity.keri.api.event.DelegatedRotationEvent;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.event.SigningThreshold.Weighted.Weight;
import foundation.identity.keri.api.event.StandardFormats;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.KeyEventCoordinatesSeal;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.crypto.Signature;
import foundation.identity.keri.internal.ImmutableVersion;
import foundation.identity.keri.internal.event.ImmutableAttachmentEvent;
import foundation.identity.keri.internal.event.ImmutableEventSignature;
import foundation.identity.keri.internal.event.ImmutableInceptionEvent;
import foundation.identity.keri.internal.event.ImmutableInteractionEvent;
import foundation.identity.keri.internal.event.ImmutableKeyConfigurationDigest;
import foundation.identity.keri.internal.event.ImmutableKeyEventCoordinates;
import foundation.identity.keri.internal.event.ImmutableRotationEvent;
import foundation.identity.keri.internal.seal.ImmutableDigestSeal;
import foundation.identity.keri.internal.seal.ImmutableKeyEventCoordinatesSeal;
import foundation.identity.keri.internal.seal.ImmutableMerkleTreeRootSeal;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Map;

import static foundation.identity.keri.Hex.unhexInt;
import static foundation.identity.keri.Hex.unhexLong;
import static foundation.identity.keri.QualifiedBase64.*;
import static foundation.identity.keri.SigningThresholds.*;
import static foundation.identity.keri.api.event.EventFieldNames.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toSet;

public class KeyEventDeserializer {

  private final static byte[] KERI_BYTES = "KERI".getBytes(UTF_8);

  private final static ObjectMapper JSON = new ObjectMapper();
  private final static ObjectMapper CBOR = new ObjectMapper(new CBORFactory());
  private final static ObjectMapper MESSAGE_PACK = new ObjectMapper(new MessagePackFactory());

  public Object deserialize(byte[] bytes, Map<Integer, Signature> signatures) {
    try {
      var mapper = this.mapper(this.peekFormat(bytes));
      var rootNode = mapper.readTree(bytes);
      var type = rootNode.get("t").textValue();

      return switch (type) {
        case "icp" -> this.inception(bytes, rootNode, signatures);
        case "rot" -> this.rotation(bytes, rootNode, signatures);
        case "ixn" -> this.interaction(bytes, rootNode, signatures);
        case "dip" -> this.delegatedInception(bytes, rootNode, signatures);
        case "drt" -> this.delegatedRotation(bytes, rootNode, signatures);
        case "rct" -> this.attachments(bytes, rootNode, Map.of());
        case "vrc" -> this.attachmentsFromTransferableIdentifier(bytes, rootNode, signatures);
        default -> throw new IllegalArgumentException("Unknown event type: " + type);
      };
    } catch (Exception e) {
      throw new SerializationException(e);
    }
  }

  private ObjectMapper mapper(Format format) {
    var stdFormat = (StandardFormats) format;
    return switch (stdFormat) {
      case CBOR -> CBOR;
      case JSON -> JSON;
      case MESSAGE_PACK -> MESSAGE_PACK;
    };
  }

  private Format peekFormat(byte[] bytes) {
    var versionStringStart = indexOf(bytes, KERI_BYTES, 20) + 6;
    var format = Arrays.copyOfRange(bytes, versionStringStart, versionStringStart + 4);
    return format(new String(format, UTF_8));
  }

  private static int indexOf(byte[] a, byte[] b, int limit) {
    for (var i = 0; (i < a.length) && (i < limit) && ((i + b.length) <= a.length); i++) {
      if (Arrays.equals(a, i, i + b.length, b, 0, b.length)) {
        return i;
      }
    }
    return -1;
  }

  byte[] inceptionStatement(Format format, Identifier identifier, JsonNode rootNode) {
    var mapper = this.mapper(format);
    var copy = (ObjectNode) rootNode.deepCopy();
    copy.put(IDENTIFIER.label(), identifierPlaceholder(identifier));

    try {
      return mapper.writeValueAsBytes(copy);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  InceptionEvent inception(byte[] bytes, JsonNode rootNode, Map<Integer, Signature> signatures) {
    var versionString = rootNode.get(VERSION.label()).textValue();
    var version = version(versionString.substring(4, 6));
    var format = format(versionString.substring(6, 10));
    var prefix = identifier(rootNode.get(IDENTIFIER.label()).textValue());
    var signingThreshold = readSigningThreshold(rootNode.get(SIGNING_THRESHOLD.label()));

    var keys = new ArrayList<PublicKey>();
    var keyIterator = rootNode.get(KEYS.label()).elements();
    while (keyIterator.hasNext()) {
      var publicKey = publicKey(keyIterator.next().textValue());
      keys.add(publicKey);
    }

    var nextKeyConfiguration = new ImmutableKeyConfigurationDigest(
        digest(rootNode.get(NEXT_KEYS_DIGEST.label()).textValue()));

    var witnessThreshold = unhexInt(rootNode.get(WITNESS_THRESHOLD.label()).textValue());
    var witnesses = new ArrayList<BasicIdentifier>();
    var witnessIterator = rootNode.get(WITNESSES.label()).elements();
    while (witnessIterator.hasNext()) {
      var basicPrefix = (BasicIdentifier) identifier(witnessIterator.next().textValue());
      witnesses.add(basicPrefix);
    }

    var configurationTraits = EnumSet.noneOf(ConfigurationTrait.class);
    var traitIterator = rootNode.get(CONFIGURATION.label()).elements();
    while (traitIterator.hasNext()) {
      var trait = trait(traitIterator.next().textValue());
      configurationTraits.add(trait);
    }

    var inceptionStatement = this.inceptionStatement(format, prefix, rootNode);

    return new ImmutableInceptionEvent(
        bytes,
        inceptionStatement,
        version,
        format,
        prefix,
        signingThreshold,
        keys,
        nextKeyConfiguration,
        witnessThreshold,
        witnesses,
        configurationTraits,
        signatures,
        Map.of(),
        Map.of()
        );
  }

  static Version version(String str) {
    return new ImmutableVersion(unhexInt(str.substring(0, 1)), unhexInt(str.substring(1, 2)));
  }

  static ConfigurationTrait trait(String str) {
    return switch (str) {
      case "EO" -> ConfigurationTrait.ESTABLISHMENT_EVENTS_ONLY;
      case "DND" -> ConfigurationTrait.DO_NOT_DELEGATE;
      default -> throw new IllegalArgumentException("Unknown configuration: " + str);
    };
  }

  static StandardFormats format(String str) {
    return switch (str) {
      case "CBOR" -> StandardFormats.CBOR;
      case "JSON" -> StandardFormats.JSON;
      case "MSGP" -> StandardFormats.MESSAGE_PACK;
      default -> throw new IllegalArgumentException("Unknown format: " + str);
    };
  }

  RotationEvent rotation(byte[] bytes, JsonNode rootNode, Map<Integer, Signature> signatures) {
    var versionString = rootNode.get(VERSION.label()).textValue();
    var version = version(versionString.substring(4, 6));
    var format = format(versionString.substring(6, 10));
    var prefix = identifier(rootNode.get(IDENTIFIER.label()).textValue());
    var sequenceNumber = unhexLong(rootNode.get(SEQUENCE_NUMBER.label()).textValue());
    var previousDigest = digest(rootNode.get(PRIOR_EVENT_DIGEST.label()).textValue());
    var previous = new ImmutableKeyEventCoordinates(prefix, sequenceNumber - 1, previousDigest);
    var signingThreshold = readSigningThreshold(rootNode.get(SIGNING_THRESHOLD.label()));

    var keys = new ArrayList<PublicKey>();
    var keyIterator = rootNode.get(KEYS.label()).elements();
    while (keyIterator.hasNext()) {
      var publicKey = publicKey(keyIterator.next().textValue());
      keys.add(publicKey);
    }

    var nextKeyConfiguration = new ImmutableKeyConfigurationDigest(
        digest(rootNode.get(NEXT_KEYS_DIGEST.label()).textValue()));

    var witnessThreshold = unhexInt(rootNode.get(WITNESS_THRESHOLD.label()).textValue());

    var removedWitnesses = new ArrayList<BasicIdentifier>();
    var removedWitnessesIterator = rootNode.get(WITNESSES_REMOVED.label()).elements();
    while (removedWitnessesIterator.hasNext()) {
      // TODO send to specialized QualifierBase64.basicPrefix()
      var basicPrefix = (BasicIdentifier) identifier(removedWitnessesIterator.next().textValue());
      removedWitnesses.add(basicPrefix);
    }

    var addedWitnesses = new ArrayList<BasicIdentifier>();
    var addedWitnessesIterator = rootNode.get(WITNESSES_ADDED.label()).elements();
    while (addedWitnessesIterator.hasNext()) {
      // TODO send to specialized QualifierBase64.basicPrefix()
      var basicPrefix = (BasicIdentifier) identifier(addedWitnessesIterator.next().textValue());
      addedWitnesses.add(basicPrefix);
    }

    var seals = new ArrayList<Seal>();
    var sealIterator = rootNode.get(ANCHORS.label()).elements();
    while (sealIterator.hasNext()) {
      var seal = readSeal(sealIterator.next());
      seals.add(seal);
    }

    return new ImmutableRotationEvent(
        version,
        format,
        prefix,
        sequenceNumber,
        previous,
        signingThreshold,
        keys,
        nextKeyConfiguration,
        witnessThreshold,
        removedWitnesses,
        addedWitnesses,
        seals,
        bytes,
        signatures,
        Map.of(),
        Map.of());
  }

  static SigningThreshold readSigningThreshold(JsonNode jsonNode) {
    if (jsonNode.isTextual()) {
      return unweighted(unhexInt(jsonNode.textValue()));
    } else if (jsonNode.isArray()) {
      if (jsonNode.get(0).isTextual()) {
        var i = jsonNode.iterator();
        var weights = new ArrayList<Weight>();
        while (i.hasNext()) {
          weights.add(weight(i.next().textValue()));
        }
        return weighted(weights.toArray(Weight[]::new));
      } else if (jsonNode.get(0).isArray()) {
        var groups = new Weight[jsonNode.size()][];

        var groupsIter = jsonNode.iterator();
        for (var i = 0; groupsIter.hasNext(); i++) {
          var weights = groupsIter.next();
          groups[i] = new Weight[weights.size()];
          var weightsIter = weights.iterator();
          for (var j = 0; weightsIter.hasNext(); j++) {
            groups[i][j] = weight(weightsIter.next().textValue());
          }
        }
        return weighted(groups);
      } else {
        throw new IllegalArgumentException("unknown threshold structure: " + jsonNode);
      }
    } else {
      throw new IllegalArgumentException("unknown threshold type: " + jsonNode);
    }
  }

  static Seal readSeal(JsonNode jsonNode) {
    if (jsonNode.has("i")) {
      return new ImmutableKeyEventCoordinatesSeal(
          new ImmutableKeyEventCoordinates(
              identifier(jsonNode.get("i").textValue()),
              unhexLong(jsonNode.get("s").textValue()),
              digest(jsonNode.get("d").textValue())));
    } else if (jsonNode.has("rd")) {
      return new ImmutableMerkleTreeRootSeal(digest(jsonNode.get("rd").textValue()));
    } else if (jsonNode.has("d")) {
      return new ImmutableDigestSeal(digest(jsonNode.get("d").textValue()));
    } else {
      return new UnknownSeal(jsonNode);
    }

  }

  InteractionEvent interaction(byte[] bytes, JsonNode rootNode, Map<Integer, Signature> signatures) {
    var versionString = rootNode.get(VERSION.label()).textValue();
    var version = version(versionString.substring(4, 6));
    var format = format(versionString.substring(6, 10));
    var prefix = identifier(rootNode.get(IDENTIFIER.label()).textValue());
    var sequenceNumber = unhexLong(rootNode.get(SEQUENCE_NUMBER.label()).textValue());
    var previousDigest = digest(rootNode.get(PRIOR_EVENT_DIGEST.label()).textValue());
    var previous = new ImmutableKeyEventCoordinates(prefix, sequenceNumber - 1, previousDigest);

    var seals = new ArrayList<Seal>();
    var sealIterator = rootNode.get(ANCHORS.label()).elements();
    while (sealIterator.hasNext()) {
      var seal = readSeal(sealIterator.next());
      seals.add(seal);
    }

    return new ImmutableInteractionEvent(
        version,
        format,
        prefix,
        sequenceNumber,
        previous,
        seals,
        bytes,
        signatures,
        Map.of(),
        Map.of());
  }

  AttachmentEvent attachmentsFromTransferableIdentifier(
      byte[] bytes, JsonNode rootNode, Map<Integer, Signature> signatures) {
    var versionString = rootNode.get(VERSION.label()).textValue();
    var version = version(versionString.substring(4, 6));
    var format = format(versionString.substring(6, 10));
    var identifier = identifier(rootNode.get(IDENTIFIER.label()).textValue());
    var sequenceNumber = unhexLong(rootNode.get(SEQUENCE_NUMBER.label()).textValue());
    var eventDigest = digest(rootNode.get(EVENT_DIGEST.label()).textValue());
    var eventCoordinates = new ImmutableKeyEventCoordinates(identifier, sequenceNumber, eventDigest);

    var seal = (KeyEventCoordinatesSeal) readSeal(rootNode.get(ANCHORS.label()));

    return new ImmutableAttachmentEvent(
        eventCoordinates,
        Map.of(),
        Map.of(),
        Map.of(seal.event(), signatures));
  }

  AttachmentEvent attachments(
      byte[] bytes, JsonNode rootNode, Map<BasicIdentifier, Signature> signatures) {
    var versionString = rootNode.get(VERSION.label()).textValue();
    var version = version(versionString.substring(4, 6));
    var format = format(versionString.substring(6, 10));
    var identifier = identifier(rootNode.get(IDENTIFIER.label()).textValue());
    var sequenceNumber = unhexLong(rootNode.get(SEQUENCE_NUMBER.label()).textValue());
    var eventDigest = digest(rootNode.get(EVENT_DIGEST.label()).textValue());
    var eventCoordinates = new ImmutableKeyEventCoordinates(identifier, sequenceNumber, eventDigest);

    var eventSignatures = signatures.entrySet()
        .stream()
        .map(e -> {
          var keyCoordinates = ImmutableKeyEventCoordinates.of(e.getKey());
          return (EventSignature) new ImmutableEventSignature(
              eventCoordinates, keyCoordinates, Map.of(0, e.getValue()));
        })
        .collect(toSet());

    // FIXME this is broken until attachments are refactored.
    return new ImmutableAttachmentEvent(
        eventCoordinates,
        Map.of(),
        Map.of(),
        Map.of());
  }

  DelegatedInceptionEvent delegatedInception(byte[] bytes, JsonNode rootNode, Map<Integer, Signature> signatures) {
    // TODO Auto-generated method stub
    return null;
  }

  DelegatedRotationEvent delegatedRotation(byte[] bytes, JsonNode rootNode, Map<Integer, Signature> signatures) {
    // TODO Auto-generated method stub
    return null;
  }

  public static class UnknownSeal implements Seal {

    private final JsonNode jsonNode;

    public UnknownSeal(JsonNode jsonNode) {
      this.jsonNode = jsonNode;
    }

    public JsonNode jsonNode() {
      return this.jsonNode;
    }

  }

}
