package foundation.identity.keri.controller;

import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.EstablishmentEvent;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.api.seal.Seal;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class DefaultControllableIdentifier implements ControllableIdentifier {

  public final Controller controller;
  private final KeyState state;

  public DefaultControllableIdentifier(Controller controller, KeyState initialState) {
    this.controller = controller;
    this.state = initialState;
  }

  @Override
  public Identifier identifier() {
    return this.state.identifier();
  }

  @Override
  public SigningThreshold signingThreshold() {
    return this.state.signingThreshold();
  }

  @Override
  public List<PublicKey> keys() {
    return this.state.keys();
  }

  @Override
  public Optional<KeyConfigurationDigest> nextKeyConfigurationDigest() {
    return this.state.nextKeyConfigurationDigest();
  }

  @Override
  public int witnessThreshold() {
    return this.state.witnessThreshold();
  }

  @Override
  public List<BasicIdentifier> witnesses() {
    return this.state.witnesses();
  }

  @Override
  public Set<ConfigurationTrait> configurationTraits() {
    return this.state.configurationTraits();
  }

  @Override
  public IdentifierEvent lastEvent() {
    return this.state.lastEvent();
  }

  @Override
  public EstablishmentEvent lastEstablishmentEvent() {
    return this.state.lastEstablishmentEvent();
  }

  @Override
  public Optional<Identifier> delegatingIdentifier() {
    return this.state.delegatingIdentifier();
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
