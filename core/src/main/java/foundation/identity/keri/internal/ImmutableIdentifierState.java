package foundation.identity.keri.internal;

import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class ImmutableIdentifierState implements IdentifierState {

  private final Identifier identifier;
  private final int signingThreshold;
  private final List<PublicKey> keys;
  private final Optional<KeyConfigurationDigest> nextKeyConfigurationDigest;
  private final int witnessThreshold;
  private final List<BasicIdentifier> witnesses;
  private final Set<ConfigurationTrait> configurationTraits;
  private final IdentifierEvent lastEvent;
  private final EstablishmentEvent lastEstablishmentEvent;
  private final Optional<Identifier> delegatingIdentifier;

  public ImmutableIdentifierState(
      Identifier identifier,
      int signingThreshold,
      List<PublicKey> keys,
      KeyConfigurationDigest nextKeyConfigurationDigest,
      int witnessThreshold,
      List<BasicIdentifier> witnesses,
      Set<ConfigurationTrait> configurationTraits,
      IdentifierEvent lastEvent,
      EstablishmentEvent lastEstablishmentEvent,
      Identifier delegatingIdentifier) {
    this.identifier = identifier;
    this.signingThreshold = signingThreshold;
    this.keys = List.copyOf(keys);
    this.nextKeyConfigurationDigest = Optional.ofNullable(nextKeyConfigurationDigest);
    this.witnessThreshold = witnessThreshold;
    this.witnesses = List.copyOf(witnesses);
    this.configurationTraits = Set.copyOf(configurationTraits);
    this.lastEvent = lastEvent;
    this.lastEstablishmentEvent = lastEstablishmentEvent;
    this.delegatingIdentifier = Optional.ofNullable(delegatingIdentifier);
  }

  @Override
  public Identifier identifier() {
    return this.identifier;
  }

  @Override
  public int signingThreshold() {
    return this.signingThreshold;
  }

  @Override
  public List<PublicKey> keys() {
    return this.keys;
  }

  @Override
  public Optional<KeyConfigurationDigest> nextKeyConfigurationDigest() {
    return this.nextKeyConfigurationDigest;
  }

  @Override
  public int witnessThreshold() {
    return this.witnessThreshold;
  }

  @Override
  public List<BasicIdentifier> witnesses() {
    return this.witnesses;
  }

  @Override
  public Set<ConfigurationTrait> configurationTraits() {
    return this.configurationTraits;
  }

  @Override
  public IdentifierEvent lastEvent() {
    return this.lastEvent;
  }

  @Override
  public EstablishmentEvent lastEstablishmentEvent() {
    return this.lastEstablishmentEvent;
  }

  @Override
  public Optional<Identifier> delegatingIdentifier() {
    return this.delegatingIdentifier;
  }

}
