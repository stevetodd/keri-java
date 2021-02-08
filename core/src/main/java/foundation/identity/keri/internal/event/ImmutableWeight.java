package foundation.identity.keri.internal.event;

import foundation.identity.keri.api.event.SigningThreshold.Weighted.Weight;

import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

public class ImmutableWeight implements Weight {

  private final int numerator;
  private final Integer denominator;

  public ImmutableWeight(int numerator, Integer denominator) {
    this.numerator = numerator;
    this.denominator = denominator;
  }

  public ImmutableWeight(Weight weight) {
    requireNonNull(weight, "weight");
    this.numerator = weight.numerator();
    this.denominator = weight.denominator().orElse(null);
  }

  @Override
  public int numerator() {
    return this.numerator;
  }

  @Override
  public Optional<Integer> denominator() {
    return Optional.ofNullable(this.denominator);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof ImmutableWeight)) {
      return false;
    }
    Weight that = (Weight) o;
    return this.numerator == that.numerator()
        && Objects.equals(this.denominator, that.denominator().orElseGet(() -> null));
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.numerator, this.denominator);
  }

  @Override
  public String toString() {
    return this.numerator + "/" + this.denominator;
  }
}
