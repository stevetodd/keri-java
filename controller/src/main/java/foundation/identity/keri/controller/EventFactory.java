package foundation.identity.keri.controller;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.crypto.Signature;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.RotationEvent;
import foundation.identity.keri.controller.spec.IdentifierSpec;
import foundation.identity.keri.controller.spec.InteractionSpec;
import foundation.identity.keri.controller.spec.RotationSpec;
import foundation.identity.keri.internal.event.ImmutableInceptionEvent;
import foundation.identity.keri.internal.event.ImmutableInteractionEvent;
import foundation.identity.keri.internal.event.ImmutableRotationEvent;

import java.util.Map;

/**
 * @author stephen
 */
public final class EventFactory {

  private final KeyEventSerializer eventSerializer = new KeyEventSerializer();

  public InceptionEvent inception(IdentifierSpec spec) {
    var inceptionStatement = this.eventSerializer.inceptionStatement(spec);
    var prefix = IdentifierFactory.identifier(spec, inceptionStatement);
    var bytes = this.eventSerializer.serialize(prefix, spec);
    var signature = spec.signer().sign(bytes);

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
        Map.of(0, signature),
        Map.of(),
        Map.of());
  }

  public RotationEvent rotation(RotationSpec spec) {
    var bytes = this.eventSerializer.serialize(spec);
    Map<Integer, Signature> signatures = Map.of();

    if (spec.signer() != null) {
      var signature = spec.signer().sign(bytes);
      signatures = Map.of(0, signature);
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
        signatures,
        Map.of(),
        Map.of());
  }

  public InteractionEvent interaction(InteractionSpec spec) {
    var bytes = this.eventSerializer.serialize(spec);
    Map<Integer, Signature> signatures = Map.of();

    if (spec.signer() != null) {
      var signature = spec.signer().sign(bytes);
      signatures = Map.of(0, signature);
    }

    return new ImmutableInteractionEvent(
        Version.CURRENT,
        spec.format(),
        spec.identifier(),
        spec.sequenceNumber(),
        spec.previous(),
        spec.seals(),
        bytes,
        signatures,
        Map.of(),
        Map.of());
  }

}
