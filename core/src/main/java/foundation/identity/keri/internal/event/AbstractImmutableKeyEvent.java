package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.identifier.Identifier;

import java.util.Set;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

public abstract class AbstractImmutableKeyEvent extends AbstractImmutableEvent
    implements KeyEvent {

  private final Identifier identifier;
  private final long sequenceNumber;
  private final KeyEventCoordinates previous;
  private final Set<AttachedEventSignature> signatures;
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
      Set<AttachedEventSignature> signatures) {
    super(bytes, version, format);
    this.identifier = requireNonNull(identifier, "identifier");
    this.sequenceNumber = sequenceNumber;
    this.previous = requireNonNull(previous, "previous");
    this.signatures = Set.copyOf(requireNonNull(signatures, "signatures"));
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
    return coordinates.get();
  }

  @Override
  public KeyEventCoordinates previous() {
    return this.previous;
  }

  @Override
  public Set<AttachedEventSignature> signatures() {
    return this.signatures;
  }

}
