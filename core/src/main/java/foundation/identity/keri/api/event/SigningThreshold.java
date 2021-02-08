package foundation.identity.keri.api.event;

import java.util.List;
import java.util.Optional;

public interface SigningThreshold {

  interface Unweighted extends SigningThreshold {

    int threshold();

  }

  interface Weighted extends SigningThreshold {

    List<List<Weight>> weights();

    interface Weight {
      int numerator();
      Optional<Integer> denominator();
    }
  }

}
