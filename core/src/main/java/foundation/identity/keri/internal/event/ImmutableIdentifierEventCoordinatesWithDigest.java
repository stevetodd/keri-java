package foundation.identity.keri.internal.event;

import foundation.identity.keri.QualifiedBase64;
import foundation.identity.keri.api.crypto.Digest;
import foundation.identity.keri.api.crypto.DigestAlgorithm;
import foundation.identity.keri.api.crypto.StandardDigestAlgorithms;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.IdentifierEventCoordinates;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.DigestOperations;

import java.math.BigInteger;

public class ImmutableIdentifierEventCoordinatesWithDigest extends ImmutableIdentifierEventCoordinates
    implements IdentifierEventCoordinatesWithDigest {

  private final Digest digest;

  public ImmutableIdentifierEventCoordinatesWithDigest(IdentifierEventCoordinates coordinates, Digest digest) {
    super(coordinates);
    this.digest = digest;
  }

  public ImmutableIdentifierEventCoordinatesWithDigest(Identifier identifier, BigInteger sequenceNumber, Digest digest) {
    super(new ImmutableIdentifierEventCoordinates(identifier, sequenceNumber));
    this.digest = digest;
  }

  public ImmutableIdentifierEventCoordinatesWithDigest(IdentifierEventCoordinatesWithDigest coordinates) {
    super(coordinates);
    this.digest = coordinates.digest();
  }

  public static ImmutableIdentifierEventCoordinatesWithDigest of(IdentifierEvent event) {
    var algorithm = event.previous().equals(IdentifierEventCoordinatesWithDigest.NONE)
                    ? StandardDigestAlgorithms.DEFAULT
                    : event.previous().digest().algorithm();

    return of(event, algorithm);
  }

  public static ImmutableIdentifierEventCoordinatesWithDigest of(IdentifierEvent event, DigestAlgorithm algo) {
    return of(event, DigestOperations.lookup(algo));
  }

  public static ImmutableIdentifierEventCoordinatesWithDigest of(IdentifierEvent event, DigestOperations ops) {
    var coordinates = ImmutableIdentifierEventCoordinates.of(event);
    var digest = ops.digest(event.bytes());
    return new ImmutableIdentifierEventCoordinatesWithDigest(coordinates, digest);
  }

  @Override
  public Digest digest() {
    return this.digest;
  }

  @Override
  public String toString() {
    return String.join(":",
        QualifiedBase64.qb64(identifier()),
        sequenceNumber().toString(),
        QualifiedBase64.qb64(digest())
    );
  }

}
