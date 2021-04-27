package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.ConfigurationTrait;
import foundation.identity.keri.api.event.Format;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.KeyConfigurationDigest;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.SigningThreshold;
import foundation.identity.keri.api.identifier.BasicIdentifier;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.crypto.Signature;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
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
      SigningThreshold signingThreshold,
      List<PublicKey> keys,
      KeyConfigurationDigest nextKeys,
      int witnessThreshold,
      List<BasicIdentifier> witnesses,
      Set<ConfigurationTrait> configurationTraits,
      Map<Integer, Signature> signatures,
      Map<Integer, Signature> receipts,
      Map<KeyEventCoordinates, Map<Integer, Signature>> otherReceipts) {
    super(
        version,
        format,
        identifier,
        0L,
        KeyEventCoordinates.NONE,
        signingThreshold,
        keys,
        nextKeys,
        witnessThreshold,
        bytes,
        signatures,
        receipts,
        otherReceipts);
    this.inceptionStatement = requireNonNull(inceptionStatement, "inceptionStatement").clone();
    this.witnesses = List.copyOf(requireNonNull(witnesses, "witnesses"));
    this.configurationTraits = Set.copyOf(requireNonNull(configurationTraits, "configurationTraits"));
  }

  @Override
  public byte[] inceptionStatement() {
    return this.inceptionStatement.clone();
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
