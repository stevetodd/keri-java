package foundation.identity.keri.controller;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.ReceiptFromBasicIdentifierEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferableIdentifierEvent;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.controller.spec.IdentifierSpec;
import foundation.identity.keri.controller.spec.InteractionSpec;
import foundation.identity.keri.controller.spec.ReceiptFromTransferableIdentifierSpec;
import foundation.identity.keri.controller.spec.ReceiptSpec;
import foundation.identity.keri.controller.spec.RotationSpec;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.internal.event.ImmutableAttachedEventSignature;
import foundation.identity.keri.internal.event.ImmutableKeyEventCoordinates;
import foundation.identity.keri.internal.event.ImmutableInceptionEvent;
import foundation.identity.keri.internal.event.ImmutableInteractionEvent;
import foundation.identity.keri.internal.event.ImmutableReceiptFromBasicIdentifierEvent;
import foundation.identity.keri.internal.event.ImmutableReceiptFromTransferableIdentifierEvent;
import foundation.identity.keri.internal.event.ImmutableRotationEvent;

import java.util.HashSet;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 * @author stephen
 */
public final class EventFactory {

  private final EventSerializer eventSerializer = new EventSerializer();

  public InceptionEvent inception(IdentifierSpec spec) {
    var inceptionStatement = this.eventSerializer.inceptionStatement(spec);
    var prefix = IdentifierFactory.identifier(spec, inceptionStatement);
    var bytes = this.eventSerializer.serialize(prefix, spec);

    var digest = DigestOperations.BLAKE3_256.digest(bytes);
    var event = new ImmutableKeyEventCoordinates(prefix, 0, digest);
    var signature = spec.signer().sign(bytes);
    var eventSignature = new ImmutableAttachedEventSignature(event, 0, signature);

    return new ImmutableInceptionEvent(
        bytes,
        inceptionStatement,
        Version.CURRENT,
        spec.format(),
        prefix,
        spec.signingThreshold(),
        spec.keys(),
        spec.nextKeys(),
        spec.witnessThreshold(),
        spec.witnesses(),
        spec.configurationTraits(),
        Set.of(eventSignature));
  }

  public RotationEvent rotation(RotationSpec spec) {
    var bytes = this.eventSerializer.serialize(spec);
    var signatures = new HashSet<AttachedEventSignature>();

    if (spec.signer() != null) {
      var digest = DigestOperations.BLAKE3_256.digest(bytes);
      var event = new ImmutableKeyEventCoordinates(spec.identifier(), spec.sequenceNumber(), digest);
      var signature = spec.signer().sign(bytes);
      var eventSignature = new ImmutableAttachedEventSignature(event, spec.signer().keyIndex(), signature);
      signatures.add(eventSignature);
    }

    return new ImmutableRotationEvent(
        Version.CURRENT,
        spec.format(),
        spec.identifier(),
        spec.sequenceNumber(),
        spec.previous(),
        spec.signingThreshold(),
        spec.keys(),
        spec.nextKeys(),
        spec.witnessThreshold(),
        spec.removedWitnesses(),
        spec.addedWitnesses(),
        spec.seals(),
        bytes,
        signatures);
  }

  public InteractionEvent interaction(InteractionSpec spec) {
    var bytes = this.eventSerializer.serialize(spec);
    var signatures = new HashSet<AttachedEventSignature>();

    if (spec.signer() != null) {
      var digest = DigestOperations.BLAKE3_256.digest(bytes);
      var event = new ImmutableKeyEventCoordinates(spec.identifier(), spec.sequenceNumber(), digest);
      var signature = spec.signer().sign(bytes);
      var eventSignature = new ImmutableAttachedEventSignature(event, spec.signer().keyIndex(), signature);
      signatures.add(eventSignature);
    }

    return new ImmutableInteractionEvent(
        Version.CURRENT,
        spec.format(),
        spec.identifier(),
        spec.sequenceNumber(),
        spec.previous(),
        spec.seals(),
        bytes,
        signatures);
  }

  public ReceiptFromBasicIdentifierEvent receipt(ReceiptSpec spec) {
    var bytes = this.eventSerializer.serialize(spec);

    return new ImmutableReceiptFromBasicIdentifierEvent(
        bytes,
        Version.CURRENT,
        spec.format(),
        spec.receipts()
    );
  }

  public ReceiptFromTransferableIdentifierEvent receipt(ReceiptFromTransferableIdentifierSpec spec) {
    if (spec.signatures().isEmpty()) {
      throw new IllegalArgumentException("spec signatures are required");
    }

    var bytes = this.eventSerializer.serialize(spec);
    var keyEstablishmentEvent = spec.signatures().iterator().next().key().establishmentEvent();
    var attachedSignatures = spec.signatures().stream()
        .map(ImmutableAttachedEventSignature::convert)
        .map(as -> (AttachedEventSignature) as)
        .collect(toSet());

    return new ImmutableReceiptFromTransferableIdentifierEvent(
        bytes,
        Version.CURRENT,
        spec.format(),
        spec.event(),
        keyEstablishmentEvent,
        attachedSignatures
    );
  }

}
