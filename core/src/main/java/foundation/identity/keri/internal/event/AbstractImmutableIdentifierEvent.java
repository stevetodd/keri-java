package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Set;

import static java.util.Objects.requireNonNull;

public abstract class AbstractImmutableIdentifierEvent extends AbstractImmutableEvent
    implements IdentifierEvent {

  private final Identifier identifier;

  private final BigInteger sequenceNumber;

  private final IdentifierEventCoordinatesWithDigest previous;

  private final Set<EventSignature> signatures;

  public AbstractImmutableIdentifierEvent(
      Version version,
      Format format,
      Identifier identifier,
      BigInteger sequenceNumber,
      IdentifierEventCoordinatesWithDigest previous,
      byte[] bytes,
      Set<EventSignature> signatures) {
    super(bytes, version, format);
    requireNonNull(identifier);
    requireNonNull(sequenceNumber);
    requireNonNull(bytes);
    requireNonNull(signatures);

    this.identifier = identifier;
    this.sequenceNumber = sequenceNumber;
    this.previous = previous;
    this.signatures = Set.copyOf(signatures);
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
  public IdentifierEventCoordinatesWithDigest previous() {
    return this.previous;
  }

  @Override
  public Set<EventSignature> signatures() {
    return this.signatures;
  }

}
