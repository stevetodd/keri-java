package foundation.identity.keri;

import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.util.Optional;
import java.util.stream.Stream;

public interface EventSource {

  Stream<IdentifierEvent> find(Identifier identifier);

  Stream<IdentifierEvent> find(Identifier identifier, BigInteger from);

  Optional<EventSignature> findLatestReceipt(Identifier forIdentifier, Identifier byIdentifier);

}
