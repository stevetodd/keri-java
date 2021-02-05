package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.EventSignature;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.IdentifierEventCoordinatesWithDigest;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

public final class ImmutableInceptionEvent extends AbstractImmutableEstablishmentEvent implements InceptionEvent {

  private final byte[] inceptionStatement;
  private final List<BasicIdentifier> witnesses;
  private final Set<ConfigurationTrait> configurationTraits;

  public ImmutableInceptionEvent(
      byte[] bytes,
      byte[] inceptionStatement,
      Version version,
      Format format,
      Identifier identifier,
      int signingThreshold,
      List<PublicKey> keys,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
      List<BasicIdentifier> witnesses,
      Set<ConfigurationTrait> configurationTraits,
      Set<EventSignature> signatures) {
    super(
        version,
        format,
        identifier,
        BigInteger.ZERO,
        IdentifierEventCoordinatesWithDigest.NONE,
        signingThreshold,
        keys,
        nextKeys,
        witnessThreshold,
        bytes,
        signatures);

    requireNonNull(inceptionStatement);
    requireNonNull(witnesses);
    requireNonNull(configurationTraits);

    this.inceptionStatement = inceptionStatement.clone();
    this.witnesses = List.copyOf(witnesses);
    this.configurationTraits = Set.copyOf(configurationTraits);
  }

  @Override
  public byte[] inceptionStatement() {
    return this.inceptionStatement;
  }

  @Override
  public List<BasicIdentifier> witnesses() {
    return this.witnesses;
  }

  @Override
  public Set<ConfigurationTrait> configurationTraits() {
    return this.configurationTraits;
  }

}