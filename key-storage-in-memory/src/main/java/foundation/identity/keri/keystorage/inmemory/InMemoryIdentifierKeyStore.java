package foundation.identity.keri.keystorage.inmemory;

import foundation.identity.keri.IdentifierKeyStore;
import foundation.identity.keri.api.event.KeyCoordinates;
import foundation.identity.keri.internal.event.ImmutableKeyCoordinates;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class InMemoryIdentifierKeyStore implements IdentifierKeyStore {

  private final Map<ImmutableKeyCoordinates, KeyPair> keys = new HashMap<>();
  private final Map<ImmutableKeyCoordinates, KeyPair> nextKeys = new HashMap<>();

  @Override
  public void storeKey(KeyCoordinates coordinates, KeyPair keyPair) {
    this.keys.put(new ImmutableKeyCoordinates(coordinates), keyPair);
  }

  @Override
  public Optional<KeyPair> getKey(KeyCoordinates keyCoordinates) {
    keyCoordinates = new ImmutableKeyCoordinates(keyCoordinates);
    // TODO digest algorithm agility--need to re-hash if not found
    return Optional.ofNullable(this.keys.get(keyCoordinates));
  }

  @Override
  public Optional<KeyPair> removeKey(KeyCoordinates keyCoordinates) {
    keyCoordinates = new ImmutableKeyCoordinates(keyCoordinates);
    // TODO digest algorithm agility--need to re-hash if not found
    return Optional.ofNullable(this.keys.remove(keyCoordinates));
  }

  @Override
  public void storeNextKey(KeyCoordinates coordinates, KeyPair keyPair) {
    this.nextKeys.put(new ImmutableKeyCoordinates(coordinates), keyPair);
  }

  @Override
  public Optional<KeyPair> getNextKey(KeyCoordinates keyCoordinates) {
    keyCoordinates = new ImmutableKeyCoordinates(keyCoordinates);
    // TODO digest algorithm agility--need to re-hash if not found
    return Optional.ofNullable(this.nextKeys.get(keyCoordinates));
  }

  @Override
  public Optional<KeyPair> removeNextKey(KeyCoordinates keyCoordinates) {
    keyCoordinates = new ImmutableKeyCoordinates(keyCoordinates);
    // TODO digest algorithm agility--need to re-hash if not found
    return Optional.ofNullable(this.nextKeys.remove(keyCoordinates));
  }

}
