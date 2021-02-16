package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.Version;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.Format;

import java.util.Arrays;

import static java.util.Objects.requireNonNull;

public abstract class AbstractImmutableEvent implements Event {

  private final Version version;

  private final Format format;

  private final byte[] bytes;

  public AbstractImmutableEvent(
      byte[] bytes,
      Version version,
      Format format) {
    this.version = requireNonNull(version, "version");
    this.format = requireNonNull(format, "format");
    this.bytes = requireNonNull(bytes, "bytes");
  }

  @Override
  public Version version() {
    return this.version;
  }

  @Override
  public Format format() {
    return this.format;
  }

  @Override
  public byte[] bytes() {
    return this.bytes;
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.bytes);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    var other = (AbstractImmutableEvent) obj;
    return Arrays.equals(this.bytes, other.bytes);
  }

}
