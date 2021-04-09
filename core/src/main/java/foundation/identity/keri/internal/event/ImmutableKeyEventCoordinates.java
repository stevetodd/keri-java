package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.api.crypto.StandardDigestAlgorithms;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.DigestOperations;

import java.util.Objects;

import static foundation.identity.keri.QualifiedBase64.qb64;
import static java.util.Objects.requireNonNull;

public class ImmutableKeyEventCoordinates implements KeyEventCoordinates {

  private final Identifier identifier;
  private final long sequenceNumber;
  private final Digest digest;

  public ImmutableKeyEventCoordinates(Identifier identifier, long sequenceNumber, Digest digest) {
    if (sequenceNumber < 0) {
      throw new IllegalArgumentException("sequenceNumber must be >= 0");
    }

    this.identifier = requireNonNull(identifier, "identifier");
    this.sequenceNumber = sequenceNumber;

    if ((!(identifier instanceof BasicIdentifier) || sequenceNumber != 0)
        && Digest.NONE.equals(digest)){
      // Digest isn't required for BasicIdentifiers or for inception events
      throw new IllegalArgumentException("digest is required");
    }

    this.digest = requireNonNull(digest, "digest");
  }

  public static ImmutableKeyEventCoordinates convert(KeyEventCoordinates coordinates) {
    requireNonNull(coordinates, "coordinates");
    if (coordinates instanceof ImmutableKeyEventCoordinates) {
      return (ImmutableKeyEventCoordinates) coordinates;
    }

    return new ImmutableKeyEventCoordinates(
        coordinates.identifier(),
        coordinates.sequenceNumber(),
        coordinates.digest()
    );
  }

  public static ImmutableKeyEventCoordinates of(KeyEvent event) {
    requireNonNull(event, "event");
    var algorithm = event.previous().equals(KeyEventCoordinates.NONE)
        ? StandardDigestAlgorithms.DEFAULT
        : event.previous().digest().algorithm();

    return of(event, algorithm);
  }

  public static ImmutableKeyEventCoordinates of(KeyEvent event, DigestAlgorithm algorithm) {
    requireNonNull(event, "event");
    requireNonNull(algorithm, "algorithm");
    return of(event, DigestOperations.lookup(algorithm));
  }

  private static ImmutableKeyEventCoordinates of(KeyEvent event, DigestOperations ops) {
    var digest = ops.digest(event.bytes());
    return of(event, digest);
  }

  public static ImmutableKeyEventCoordinates of(KeyEvent event, Digest digest) {
    return new ImmutableKeyEventCoordinates(event.identifier(), event.sequenceNumber(), digest);
  }

  public static ImmutableKeyEventCoordinates of(KeyEventCoordinates event, Digest digest) {
    return new ImmutableKeyEventCoordinates(event.identifier(), event.sequenceNumber(), digest);
  }

  public static ImmutableKeyEventCoordinates of(BasicIdentifier identifier) {
    return new ImmutableKeyEventCoordinates(identifier, 0, Digest.NONE);
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
  public Digest digest() {
    return this.digest;
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.identifier, this.sequenceNumber, this.digest);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (obj == null) {
      return false;
    }
    if (!(obj instanceof KeyEventCoordinates)) {
      return false;
    }

    var other = (KeyEventCoordinates) obj;
    return Objects.equals(this.identifier, other.identifier())
        && this.sequenceNumber == other.sequenceNumber()
        && Objects.equals(this.digest, other.digest());
  }

  @Override
  public String toString() {
    return this.identifier + ":" + this.sequenceNumber + ":" + qb64(digest());
  }

}
