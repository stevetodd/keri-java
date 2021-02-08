package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.SigningThreshold.Weighted;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

public class ImmutableWeightedSigningThreshold implements Weighted {

  private final List<List<Weight>> weights;

  public ImmutableWeightedSigningThreshold(List<List<Weight>> weights) {
    this.weights = immutableCopy(requireNonNull(weights));
  }

  private List<List<Weight>> immutableCopy(List<List<Weight>> weights) {
    var tmpCopy = new ArrayList<List<Weight>>();
    for (var group : weights) {
      var groupCopy = new ArrayList<Weight>();
      for (var weight : group) {
        groupCopy.add(new ImmutableWeight(weight));
      }
      tmpCopy.add(List.copyOf(groupCopy));
    }
    return List.copyOf(tmpCopy);
  }

  @Override
  public List<List<Weight>> weights() {
    return weights;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Weighted)) {
      return false;
    }
    Weighted that = (Weighted) o;
    return weights.equals(that.weights());
  }

  @Override
  public int hashCode() {
    return Objects.hash(weights);
  }
}
