package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;

import java.math.BigInteger;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

public final class ImmutableInteractionEvent extends AbstractImmutableKeyEvent implements InteractionEvent {

  private final List<Seal> seals;

  public ImmutableInteractionEvent(
      Version version,
      Format format,
      Identifier identifier,
      BigInteger sequenceNumber,
      KeyEventCoordinates previous,
      List<Seal> seals,
      byte[] bytes,
      Set<AttachedEventSignature> signatures) {
    super(version,
        format,
        identifier,
        sequenceNumber,
        previous,
        bytes,
        signatures);
    this.seals = List.copyOf(requireNonNull(seals, "seals"));
  }

  @Override
  public List<Seal> seals() {
    return this.seals;
  }

}
