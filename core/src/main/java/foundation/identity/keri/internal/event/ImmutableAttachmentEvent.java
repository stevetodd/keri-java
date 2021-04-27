package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.crypto.Signature;

import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public class ImmutableAttachmentEvent implements AttachmentEvent {

  private final KeyEventCoordinates coordinates;
  private final Map<Integer, Signature> signatures;
  private final Map<Integer, Signature> receipts;
  private final Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts;

  public ImmutableAttachmentEvent(
      KeyEventCoordinates coordinates,
      Map<Integer, Signature> signatures,
      Map<Integer, Signature> receipts,
      Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts) {
    this.coordinates = requireNonNull(coordinates, "coordinates");
    this.signatures = Map.copyOf(requireNonNull(signatures, "signatures"));
    this.receipts = Map.copyOf(requireNonNull(receipts, "receipts"));
    this.otherReceipts = copyOfOtherReceipts(requireNonNull(otherReceipts, "otherReceipts"));
  }

  private static Map<KeyEventCoordinates, Map<Integer, Signature>> copyOfOtherReceipts(
      Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts) {
    return otherReceipts.entrySet()
        .stream()
        .map(e -> Map.entry(e.getKey(), Map.copyOf(e.getValue())))
        .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));
  }

  @Override
  public KeyEventCoordinates coordinates() {
    return this.coordinates;
  }

  @Override
  public Map<Integer, Signature> signatures() {
    return this.signatures;
  }

  @Override
  public Map<Integer, Signature> receipts() {
    return this.receipts;
  }

  @Override
  public Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts() {
    return this.otherReceipts;
  }
}
