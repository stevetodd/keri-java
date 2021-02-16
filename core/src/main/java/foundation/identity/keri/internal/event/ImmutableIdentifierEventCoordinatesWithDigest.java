package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.api.crypto.StandardDigestAlgorithms;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinates;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.DigestOperations;

import java.math.BigInteger;
import java.util.Objects;

import static foundation.identity.keri.QualifiedBase64.qb64;
import static java.util.Objects.requireNonNull;

public class ImmutableIdentifierEventCoordinatesWithDigest extends ImmutableIdentifierEventCoordinates
    implements IdentifierEventCoordinatesWithDigest {

  private final Digest digest;

  public ImmutableIdentifierEventCoordinatesWithDigest(Identifier identifier, BigInteger sequenceNumber, Digest digest) {
    super(identifier, sequenceNumber);

    if ((!(identifier instanceof BasicIdentifier) || !sequenceNumber.equals(BigInteger.ZERO))
        && Digest.NONE.equals(digest)){
      // Digest isn't required for BasicIdentifiers or for inception events
      throw new IllegalArgumentException("digest is required");
    }

    this.digest = requireNonNull(digest, "digest");
  }

  public static ImmutableIdentifierEventCoordinatesWithDigest convert(IdentifierEventCoordinatesWithDigest coordinates) {
    requireNonNull(coordinates, "coordinates");
    if (coordinates instanceof ImmutableIdentifierEventCoordinatesWithDigest) {
      return (ImmutableIdentifierEventCoordinatesWithDigest) coordinates;
    }

    return new ImmutableIdentifierEventCoordinatesWithDigest(
        coordinates.identifier(),
        coordinates.sequenceNumber(),
        coordinates.digest()
    );
  }

  public static ImmutableIdentifierEventCoordinatesWithDigest of(IdentifierEvent event) {
    requireNonNull(event, "event");
    var algorithm = event.previous().equals(IdentifierEventCoordinatesWithDigest.NONE)
                    ? StandardDigestAlgorithms.DEFAULT
                    : event.previous().digest().algorithm();

    return of(event, algorithm);
  }

  public static ImmutableIdentifierEventCoordinatesWithDigest of(IdentifierEvent event, DigestAlgorithm algorithm) {
    requireNonNull(event, "event");
    requireNonNull(algorithm, "algorithm");
    return of(event, DigestOperations.lookup(algorithm));
  }

  private static ImmutableIdentifierEventCoordinatesWithDigest of(IdentifierEvent event, DigestOperations ops) {
    var digest = ops.digest(event.bytes());
    return of(event, digest);
  }

  public static ImmutableIdentifierEventCoordinatesWithDigest of(IdentifierEvent event, Digest digest) {
    return new ImmutableIdentifierEventCoordinatesWithDigest(event.identifier(), event.sequenceNumber(), digest);
  }

  public static ImmutableIdentifierEventCoordinatesWithDigest of(IdentifierEventCoordinates event, Digest digest) {
    return new ImmutableIdentifierEventCoordinatesWithDigest(event.identifier(), event.sequenceNumber(), digest);
  }

  public static ImmutableIdentifierEventCoordinatesWithDigest of(BasicIdentifier identifier) {
    return new ImmutableIdentifierEventCoordinatesWithDigest(identifier, BigInteger.ZERO, Digest.NONE);
  }

  @Override
  public Digest digest() {
    return this.digest;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof IdentifierEventCoordinatesWithDigest)) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }
    var that = (IdentifierEventCoordinatesWithDigest) o;
    return Objects.equals(this.digest, that.digest());
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), this.digest);
  }

  @Override
  public String toString() {
    return super.toString() + ":" + qb64(digest());
  }

}
