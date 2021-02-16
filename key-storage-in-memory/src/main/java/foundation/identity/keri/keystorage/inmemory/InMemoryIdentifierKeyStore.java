package foundation.identity.keri.keystorage.inmemory;

import foundation.identity.keri.IdentifierKeyStore;
import foundation.identity.keri.QualifiedBase64;
import foundation.identity.keri.api.event.KeyCoordinates;
import foundation.identity.keri.internal.event.ImmutableKeyCoordinates;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Comparator.comparing;
import static java.util.Comparator.comparingInt;
import static java.util.Map.Entry.comparingByKey;

/**
 * Unsafe. For use in testing only.
 */
public class InMemoryIdentifierKeyStore implements IdentifierKeyStore {

  private final Map<ImmutableKeyCoordinates, KeyPair> keys = new HashMap<>();
  private final Map<ImmutableKeyCoordinates, KeyPair> nextKeys = new HashMap<>();

  @Override
  public void storeKey(KeyCoordinates coordinates, KeyPair keyPair) {
    this.keys.put(ImmutableKeyCoordinates.convert(coordinates), keyPair);
  }

  @Override
  public Optional<KeyPair> getKey(KeyCoordinates keyCoordinates) {
    keyCoordinates = ImmutableKeyCoordinates.convert(keyCoordinates);
    // TODO digest algorithm agility--need to re-hash if not found
    return Optional.ofNullable(this.keys.get(keyCoordinates));
  }

  @Override
  public Optional<KeyPair> removeKey(KeyCoordinates keyCoordinates) {
    keyCoordinates = ImmutableKeyCoordinates.convert(keyCoordinates);
    // TODO digest algorithm agility--need to re-hash if not found
    return Optional.ofNullable(this.keys.remove(keyCoordinates));
  }

  @Override
  public void storeNextKey(KeyCoordinates coordinates, KeyPair keyPair) {
    this.nextKeys.put(ImmutableKeyCoordinates.convert(coordinates), keyPair);
  }

  @Override
  public Optional<KeyPair> getNextKey(KeyCoordinates keyCoordinates) {
    keyCoordinates = ImmutableKeyCoordinates.convert(keyCoordinates);
    // TODO digest algorithm agility--need to re-hash if not found
    return Optional.ofNullable(this.nextKeys.get(keyCoordinates));
  }

  @Override
  public Optional<KeyPair> removeNextKey(KeyCoordinates keyCoordinates) {
    keyCoordinates = ImmutableKeyCoordinates.convert(keyCoordinates);
    // TODO digest algorithm agility--need to re-hash if not found
    return Optional.ofNullable(this.nextKeys.remove(keyCoordinates));
  }

  public void printContents() {
    System.out.println();
    System.out.println("====== IDENTIFIER KEY STORE ======");
    System.out.println("KEYS:");

    var keyIdentifierComparator = comparing((KeyCoordinates k) -> k.establishmentEvent().identifier().toString());
    var keySequenceNumberComparator = comparing((KeyCoordinates k) -> k.establishmentEvent().sequenceNumber());
    var keyEventDigestComparator = comparing((KeyCoordinates k) -> k.establishmentEvent().digest().toString());
    var keyIndexComparator = comparingInt(KeyCoordinates::keyIndex);
    var keyCoordinatesComparator = keyIdentifierComparator.thenComparing(keySequenceNumberComparator)
        .thenComparing(keyEventDigestComparator)
        .thenComparing(keyIndexComparator);

    keys.entrySet().stream()
        .sorted(comparingByKey(keyCoordinatesComparator))
        .forEachOrdered(kv -> {
          System.out.println(kv.getKey() + " -> " + QualifiedBase64.qb64(kv.getValue().getPublic()));
        });

    System.out.println("NEXT KEYS:");
    nextKeys.entrySet().stream()
        .sorted(comparingByKey(keyCoordinatesComparator))
        .forEachOrdered(kv -> {
          System.out.println(kv.getKey() + " -> " + QualifiedBase64.qb64(kv.getValue().getPublic()));
        });

    System.out.println("=========================");
    System.out.println();
  }

}
