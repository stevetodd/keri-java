package foundation.identity.keri;

import foundation.identity.keri.api.event.SigningThreshold.Weighted.Weight;
import org.junit.Test;

import java.util.List;

import static foundation.identity.keri.SigningThresholds.*;
import static org.junit.Assert.*;

public class SigningThresholdTests {

  @Test
  public void test__weight__int_int() {
    assertWeightValue(weight(1, 1), 1, 1);
    assertWeightValue(weight(1 ,2), 1, 2);

    assertWeightValue(weight(2 ,1), 2, 1);
    assertWeightValue(weight(2 ,2), 2, 2);

    assertWeightValue(weight(2 ,3), 2, 3);
    assertWeightValue(weight(3 ,2), 3, 2);

    assertThrows(IllegalArgumentException.class, () -> weight(0, 1));
    assertThrows(IllegalArgumentException.class, () -> weight(1, 0));
    assertThrows(IllegalArgumentException.class, () -> weight(-1, 2));
    assertThrows(IllegalArgumentException.class, () -> weight(1, -2));
    assertThrows(IllegalArgumentException.class, () -> weight(-1, -2));
  }

  @Test
  public void test__weight__int() {
    assertThrows(IllegalArgumentException.class, () -> weight(-1));
    assertThrows(IllegalArgumentException.class, () -> weight(0));

    assertEquals(weight(1), weight(1, 1));
    assertEquals(weight(2), weight(2, 1));
  }

  @Test
  public void test__weight__String() {
    assertEquals(weight("1/1"), weight(1, 1));
    assertEquals(weight("1/2"), weight(1, 2));

    assertEquals(weight("2/1"), weight(2, 1));
    assertEquals(weight("2/2"), weight(2, 2));

    assertEquals(weight("2/3"), weight(2, 3));
    assertEquals(weight("3/2"), weight(3, 2));


    assertThrows(IllegalArgumentException.class, () -> weight("0/1"));
    assertThrows(IllegalArgumentException.class, () -> weight("1/0"));
    assertThrows(IllegalArgumentException.class, () -> weight("-1/2"));
    assertThrows(IllegalArgumentException.class, () -> weight("1/-2"));
    assertThrows(IllegalArgumentException.class, () -> weight("-1/-2"));
  }

  private void assertWeightValue(Weight w, int expectedNumerator, int expectedDenominator) {
    assertEquals("numerator", expectedNumerator, w.numerator());
    assertEquals("denominator", (Integer) expectedDenominator, w.denominator().orElse(null));
  }

  @Test
  public void test__unweighted() {
    assertThrows(IllegalArgumentException.class, () -> unweighted(-1));
    assertThrows(IllegalArgumentException.class, () -> unweighted(0));
  }

  @Test
  public void test__weighted() {
    assertEquals(weighted(group("1")), weighted("1"));

    assertEquals(
        weighted(
            group(
              weight(1, 2),
              weight(1, 2),
              weight(1, 4),
              weight(1, 4),
              weight(1, 4)
              )),
        weighted("1/2", "1/2", "1/4", "1/4", "1/4"));

    assertEquals(
        weightedWithGroups(
            group(
                weight(1, 2),
                weight(1, 2),
                weight(1, 4),
                weight(1, 4),
                weight(1, 4)
                ),
            group(
                weight(1, 1),
                weight(1, 1)
                )),
        weightedWithGroups(
            group("1/2", "1/2", "1/4", "1/4", "1/4"),
            group("1", "1")));
  }

  @Test
  public void test__weighted__WeightArray() {
    assertThrows(IllegalArgumentException.class, () -> weighted(weight("1/3"), weight("1/2")));
    assertThrows(IllegalArgumentException.class, () -> weightedWithGroups(group("1/3", "1/2"), group("1")));
    assertThrows(IllegalArgumentException.class, () -> weighted("0/1"));
    assertThrows(IllegalArgumentException.class, () -> weighted("1/0"));
  }

  @Test
  public void test__weighted__StringArray() {
    assertThrows(IllegalArgumentException.class, () -> weighted("1/3", "1/2"));
    assertThrows(IllegalArgumentException.class, () -> weightedWithGroups(group("1/3", "1/2"), group("1")));
    assertThrows(IllegalArgumentException.class, () -> weighted("0/1"));
    assertThrows(IllegalArgumentException.class, () -> weighted("1/0"));
  }

  @Test
  public void test__thresholdMet__Unweighted() {
    assertFalse(thresholdMet(unweighted(2), List.of(0)));
    assertTrue(thresholdMet(unweighted(2), List.of(0, 1)));
    assertTrue(thresholdMet(unweighted(2), List.of(0, 1, 2)));
  }

  @Test
  public void test__thresholdMet__Weighted() {
    assertTrue(thresholdMet(weighted(weight(1)), List.of(0)));

    var threshold = weighted("1", "1");
    assertFalse(thresholdMet(threshold, List.of()));
    assertTrue(thresholdMet(threshold, List.of(0)));
    assertTrue(thresholdMet(threshold, List.of(1)));
    assertTrue(thresholdMet(threshold, List.of(0, 1)));

    threshold = weighted("1/2", "1/2", "1/4", "1/4", "1/4");
    assertTrue(thresholdMet(threshold, List.of(0, 2, 4)));
    assertTrue(thresholdMet(threshold, List.of(0, 1)));
    assertTrue(thresholdMet(threshold, List.of(1, 3, 4)));
    assertTrue(thresholdMet(threshold, List.of(0, 1, 2, 3, 4)));
    assertTrue(thresholdMet(threshold, List.of(3, 2, 0)));
    assertTrue(thresholdMet(threshold, List.of(0, 0, 1, 2, 1)));
    assertFalse(thresholdMet(threshold, List.of(0, 2)));
    assertFalse(thresholdMet(threshold, List.of(2, 3, 4)));

    threshold = weighted(group("1/2", "1/2", "1/4", "1/4", "1/4"));
    assertTrue(thresholdMet(threshold, List.of(0, 2, 4)));
    assertTrue(thresholdMet(threshold, List.of(0, 1)));
    assertTrue(thresholdMet(threshold, List.of(1, 3, 4)));
    assertTrue(thresholdMet(threshold, List.of(0, 1, 2, 3, 4)));
    assertTrue(thresholdMet(threshold, List.of(3, 2, 0)));
    assertTrue(thresholdMet(threshold, List.of(0, 0, 1, 2, 1)));
    assertFalse(thresholdMet(threshold, List.of(0, 2)));
    assertFalse(thresholdMet(threshold, List.of(2, 3, 4)));

    //noinspection unchecked
    threshold = weightedWithGroups(
        group("1/2", "1/2", "1/4", "1/4", "1/4"),
        group("1", "1"));
    assertTrue(thresholdMet(threshold, List.of(1, 2, 3, 5)));
    assertTrue(thresholdMet(threshold, List.of(0, 1, 6)));
    assertFalse(thresholdMet(threshold, List.of(0, 1)));
    assertFalse(thresholdMet(threshold, List.of(5, 6)));
    assertFalse(thresholdMet(threshold, List.of(2, 3, 4)));
    assertFalse(thresholdMet(threshold, List.of()));
  }

}
