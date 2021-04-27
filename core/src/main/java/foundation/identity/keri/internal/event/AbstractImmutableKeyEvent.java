package foundation.identity.keri.internal.event;

import foundation.identity.keri.KeyEvents;
import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.Signature;

import java.util.Map;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

public abstract class AbstractImmutableKeyEvent implements KeyEvent {

  private final Version version;
  private final Format format;
  private final byte[] bytes;
  private final Identifier identifier;
  private final long sequenceNumber;
  private final KeyEventCoordinates previous;
  private final Map<Integer, Signature> signatures;
  private final Map<Integer, Signature> receipts;
  private final Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts;

  // for lazily computing the event's coordinates
  private Supplier<KeyEventCoordinates> coordinates = () -> {
    // with multiple threads this might be ran multiple times concurrently, and that's ok
    var coordinates = ImmutableKeyEventCoordinates.of(this);
    this.coordinates = () -> coordinates;
    return coordinates;
  };

  public AbstractImmutableKeyEvent(
      Version version,
      Format format,
      Identifier identifier,
      long sequenceNumber,
      KeyEventCoordinates previous,
      byte[] bytes,
      Map<Integer, Signature> signatures,
      Map<Integer, Signature> receipts,
      Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts) {
    this.version = requireNonNull(version, "version");
    this.format = requireNonNull(format, "format");
    this.bytes = requireNonNull(bytes, "bytes");
    this.identifier = requireNonNull(identifier, "identifier");
    this.sequenceNumber = sequenceNumber;
    this.previous = requireNonNull(previous, "previous");
    this.signatures = Map.copyOf(requireNonNull(signatures, "signatures"));
    this.receipts = Map.copyOf(requireNonNull(receipts, "receipts"));
    this.otherReceipts = Map.copyOf(requireNonNull(otherReceipts, "otherReceipts"));
  }

  @Override
  public Version version() {
    return this.version;
  }

  @Override
  public Format format() {
    return this.format;
  }

  @Override
  public byte[] bytes() {
    return this.bytes.clone();
  }

  @Override
  public Identifier identifier() {
    return this.identifier;
  }

  @Override
  public long sequenceNumber() {
    return this.sequenceNumber;
  }

  @Override
  public KeyEventCoordinates coordinates() {
    return this.coordinates.get();
  }

  @Override
  public KeyEventCoordinates previous() {
    return this.previous;
  }

  @Override
  public Map<Integer, Signature> authentication() {
    return this.signatures;
  }

  @Override
  public Map<Integer, Signature> endorsements() {
    return this.receipts;
  }

  @Override
  public Map<KeyEventCoordinates, Map<Integer, Signature>> receipts() {
    return this.otherReceipts;
  }

  @Override
  public String toString() {
    return KeyEvents.toString(this);
  }
}
