package foundation.identity.keri.controller;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.ReceiptEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferrableIdentifierEvent;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.controller.spec.IdentifierSpec;
import foundation.identity.keri.controller.spec.InteractionSpec;
import foundation.identity.keri.controller.spec.ReceiptFromTransferrableIdentifierSpec;
import foundation.identity.keri.controller.spec.ReceiptSpec;
import foundation.identity.keri.controller.spec.RotationSpec;
import foundation.identity.keri.crypto.DigestOperations;
import foundation.identity.keri.internal.event.ImmutableEventSignature;
import foundation.identity.keri.internal.event.ImmutableIdentifierEventCoordinates;
import foundation.identity.keri.internal.event.ImmutableIdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.internal.event.ImmutableInceptionEvent;
import foundation.identity.keri.internal.event.ImmutableInteractionEvent;
import foundation.identity.keri.internal.event.ImmutableKeyCoordinates;
import foundation.identity.keri.internal.event.ImmutableReceiptEvent;
import foundation.identity.keri.internal.event.ImmutableReceiptFromTransferrableIdentifierEvent;
import foundation.identity.keri.internal.event.ImmutableRotationEvent;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

/**
 * @author stephen
 */
public final class EventFactory {

  private final EventSerializer eventSerializer = new EventSerializer();

  public InceptionEvent inception(IdentifierSpec spec) {
    var inceptionStatement = this.eventSerializer.inceptionStatement(spec);
    var prefix = IdentifierFactory.identifier(spec, inceptionStatement);
    var bytes = this.eventSerializer.serialize(prefix, spec);
    var signature = spec.signer().sign(bytes);
    var eventCoordinates = new ImmutableIdentifierEventCoordinates(prefix, BigInteger.ZERO);
    var digest = DigestOperations.BLAKE3_256.digest(bytes);
    var eventCoordinatesWitDigest = new ImmutableIdentifierEventCoordinatesWithDigest(eventCoordinates, digest);
    var keyCoordinates = new ImmutableKeyCoordinates(eventCoordinatesWitDigest, 0);
    var eventSignature = ImmutableEventSignature.of(eventCoordinatesWitDigest, keyCoordinates, signature);

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
    var signatures = new HashSet<EventSignature>();

    if (spec.signer() != null) {
      var signature = spec.signer().sign(bytes);
      var eventCoordinates = new ImmutableIdentifierEventCoordinates(spec.identifier(), spec.sequenceNumber());
      var digest = DigestOperations.BLAKE3_256.digest(bytes);
      var eventCoordinatesWitDigest = new ImmutableIdentifierEventCoordinatesWithDigest(eventCoordinates, digest);
      var keyCoordinates = new ImmutableKeyCoordinates(eventCoordinatesWitDigest, 0);
      var eventSignature = ImmutableEventSignature.of(eventCoordinatesWitDigest, keyCoordinates, signature);
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

    return new ImmutableInteractionEvent(
        Version.CURRENT,
        spec.format(),
        spec.identifier(),
        spec.sequenceNumber(),
        spec.previous(),
        spec.seals(),
        bytes,
        Set.of());
  }

  public ReceiptEvent receipt(
      ReceiptSpec spec) {
    var bytes = this.eventSerializer.serialize(spec);

    return new ImmutableReceiptEvent(
        bytes,
        Version.CURRENT,
        spec.format(),
        spec.receipts()
    );
  }

  public ReceiptFromTransferrableIdentifierEvent receipt(ReceiptFromTransferrableIdentifierSpec spec) {
    var bytes = this.eventSerializer.serialize(spec);

    return new ImmutableReceiptFromTransferrableIdentifierEvent(
        bytes,
        Version.CURRENT,
        spec.format(),
        spec.receipt()
    );
  }

}
