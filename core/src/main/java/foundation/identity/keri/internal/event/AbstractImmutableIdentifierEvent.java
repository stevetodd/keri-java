package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.AttachedEventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Set;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

public abstract class AbstractImmutableIdentifierEvent extends AbstractImmutableEvent
    implements IdentifierEvent {

  private final Identifier identifier;
  private final BigInteger sequenceNumber;
  private final IdentifierEventCoordinatesWithDigest previous;
  private final Set<AttachedEventSignature> signatures;
  private Supplier<IdentifierEventCoordinatesWithDigest> coordinates = () -> {
    // with multiple threads this might be ran multiple times concurrently, and that's ok
    var coordinates = ImmutableIdentifierEventCoordinatesWithDigest.of(this);
    this.coordinates = () -> coordinates;
    return coordinates;
  };

  public AbstractImmutableIdentifierEvent(
      Version version,
      Format format,
      Identifier identifier,
      BigInteger sequenceNumber,
      IdentifierEventCoordinatesWithDigest previous,
      byte[] bytes,
      Set<AttachedEventSignature> signatures) {
    super(bytes, version, format);
    this.identifier = requireNonNull(identifier, "identifier");
    this.sequenceNumber = requireNonNull(sequenceNumber, "sequenceNumber");
    this.previous = requireNonNull(previous, "previous");
    this.signatures = Set.copyOf(requireNonNull(signatures, "signatures"));
  }

  @Override
  public Identifier identifier() {
    return this.identifier;
  }

  @Override
  public BigInteger sequenceNumber() {
    return this.sequenceNumber;
  }

  @Override
  public IdentifierEventCoordinatesWithDigest coordinates() {
    return coordinates.get();
  }

  @Override
  public IdentifierEventCoordinatesWithDigest previous() {
    return this.previous;
  }

  @Override
  public Set<AttachedEventSignature> signatures() {
    return this.signatures;
  }

}
