package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.SigningThreshold.Unweighted;

import java.util.Objects;

public class ImmutableUnweightedSigningThreshold implements Unweighted {

  private final int threshold;

  public ImmutableUnweightedSigningThreshold(int threshold) {
    this.threshold = threshold;
  }

  @Override
  public int threshold() {
    return this.threshold;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Unweighted)) {
      return false;
    }
    return ((Unweighted) o).threshold() == this.threshold;
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.threshold);
  }

  @Override
  public String toString() {
    return Integer.toString(this.threshold);
  }
}
