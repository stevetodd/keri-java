package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.SigningThreshold.Weighted;

import java.util.Arrays;

import static java.util.Objects.requireNonNull;

public class ImmutableWeightedSigningThreshold implements Weighted {

  private final Weight[][] weights;

  public ImmutableWeightedSigningThreshold(Weight[][] weights) {
    this.weights = immutableCopy(requireNonNull(weights));
  }

  private Weight[][] immutableCopy(Weight[][] groups) {
    var groupsCopy = new Weight[groups.length][];
    for (var i = 0; i < groups.length; i++) {
      groupsCopy[i] = new Weight[groups[i].length];
      for (var j = 0; j < groups[i].length; j++) {
        var weight = groups[i][j];
        groupsCopy[i][j] = ImmutableWeight.of(weight);
      }
    }

    return groupsCopy;
  }

  @Override
  public Weight[][] weights() {
    return immutableCopy(this.weights);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (!(o instanceof Weighted)) {
      return false;
    }

    var that = (Weighted) o;
    return Arrays.deepEquals(this.weights, that.weights());
  }

  @Override
  public int hashCode() {
    return Arrays.deepHashCode(this.weights);
  }
}
