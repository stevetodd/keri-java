package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.InteractionEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;
import foundation.identity.keri.crypto.Signature;

import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public final class ImmutableInteractionEvent extends AbstractImmutableKeyEvent implements InteractionEvent {

  private final List<Seal> seals;

  public ImmutableInteractionEvent(
      Version version,
      Format format,
      Identifier identifier,
      long sequenceNumber,
      KeyEventCoordinates previous,
      List<Seal> seals,
      byte[] bytes,
      Map<Integer, Signature> signatures,
      Map<Integer, Signature> receipts,
      Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts) {
    super(version,
        format,
        identifier,
        sequenceNumber,
        previous,
        bytes,
        signatures,
        receipts,
        otherReceipts);
    this.seals = List.copyOf(requireNonNull(seals, "seals"));
  }

  @Override
  public List<Seal> seals() {
    return this.seals;
  }

}
