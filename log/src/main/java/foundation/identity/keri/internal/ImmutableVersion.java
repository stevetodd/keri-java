package foundation.identity.keri.internal;

import foundation.identity.keri.api.Version;

import java.util.Objects;

public class ImmutableVersion implements Version {

  private final int major;
  private final int minor;

  public ImmutableVersion(int major, int minor) {
    this.major = major;
    this.minor = minor;
  }

  @Override
  public int major() {
    return this.major;
  }

  @Override
  public int minor() {
    return this.minor;
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.major, this.minor);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof ImmutableVersion)) {
      return false;
    }
    var other = (ImmutableVersion) obj;
    return (this.major == other.major) && (this.minor == other.minor);
  }

  @Override
  public String toString() {
    return this.major + "." + this.minor;
  }
}
