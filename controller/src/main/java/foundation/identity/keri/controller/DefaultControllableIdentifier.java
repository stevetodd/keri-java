package foundation.identity.keri.controller;

import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class DefaultControllableIdentifier implements ControllableIdentifier {

  public final Controller controller;
  private final IdentifierState state;

  public DefaultControllableIdentifier(Controller controller, IdentifierState initialState) {
    this.controller = controller;
    this.state = initialState;
  }

  @Override
  public Identifier identifier() {
    return state.identifier();
  }

  @Override
  public int signingThreshold() {
    return state.signingThreshold();
  }

  @Override
  public List<PublicKey> keys() {
    return state.keys();
  }

  @Override
  public Optional<KeyConfigurationDigest> nextKeyConfigurationDigest() {
    return state.nextKeyConfigurationDigest();
  }

  @Override
  public int witnessThreshold() {
    return state.witnessThreshold();
  }

  @Override
  public List<BasicIdentifier> witnesses() {
    return state.witnesses();
  }

  @Override
  public Set<ConfigurationTrait> configurationTraits() {
    return state.configurationTraits();
  }

  @Override
  public IdentifierEvent lastEvent() {
    return state.lastEvent();
  }

  @Override
  public EstablishmentEvent lastEstablishmentEvent() {
    return state.lastEstablishmentEvent();
  }

  @Override
  public Optional<Identifier> delegatingIdentifier() {
    return state.delegatingIdentifier();
  }

  @Override
  public void rotate() {
    this.controller.rotate(this.identifier());
  }

  @Override
  public void rotate(List<Seal> seals) {
    this.controller.rotate(this.identifier(), seals);
  }

  @Override
  public void seal(List<Seal> seals) {
    this.controller.seal(this.identifier(), seals);
  }

  @Override
  public EventSignature sign(IdentifierEvent event) {
    return this.controller.sign(this.identifier(), event);
  }

}
