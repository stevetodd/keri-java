package foundation.identity.keri;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import static foundation.identity.keri.KeyEventDeserializer.readSigningThreshold;
import static foundation.identity.keri.SigningThresholds.*;
import static org.junit.Assert.assertEquals;

public class KeyEventDeserializerTest {

  final ObjectMapper mapper = new ObjectMapper();

  @Test
  public void test__readSigningThreshold__unweighted() throws JsonProcessingException {
    assertEquals(
        unweighted(1),
        readSigningThreshold(this.mapper.readTree("\"1\"")));

    assertEquals(
        unweighted(2),
        readSigningThreshold(this.mapper.readTree("\"2\"")));

    assertEquals(
        unweighted(3),
        readSigningThreshold(this.mapper.readTree("\"3\"")));
  }

  @Test
  public void test__readSigningThreshold__weighted() throws JsonProcessingException {

    // ["1/2", "1/2", "1/4", "1/4", "1/4"]
    assertEquals(
        weighted("1/2", "1/2", "1/4", "1/4", "1/4"),
        readSigningThreshold(this.mapper.readTree("[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\"]")));

    // [["1/2", "1/2", "1/4", "1/4", "1/4"]]
    assertEquals(
        weighted(
            group("1/2", "1/2", "1/4", "1/4", "1/4")),
        readSigningThreshold(this.mapper.readTree("[[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\"]]")));

    // [["1/2","1/2","1/4","1/4","1/4"],["1","1"]]
    assertEquals(
        weighted(
            group("1/2", "1/2", "1/4", "1/4", "1/4"),
            group("1", "1")),
        readSigningThreshold(this.mapper.readTree("[[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\"],[\"1\",\"1\"]]")));
  }

}
