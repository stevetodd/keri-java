package foundation.identity.keri;

import org.junit.Test;

import java.math.BigInteger;

import static foundation.identity.keri.Hex.*;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class HexTests {

  @Test
  public void testHex() {
    var bytes = new byte[]{0x01, 0x09, 0x0a, 0x0f, 0x10, (byte) 0xf0, (byte) 0xff};

    var hex = Hex.hex(bytes);

    assertEquals("01090a0f10f0ff", hex);
  }

  @Test
  public void testUnhex() {
    var bytes = Hex.unhex("01090a0f10f0ff");

    var expected = new byte[]{0x01, 0x09, 0x0a, 0x0f, 0x10, (byte) 0xf0, (byte) 0xff};
    assertArrayEquals(expected, bytes);
  }

  @Test
  public void testHexBigInteger() {
    var i = new BigInteger("75043633293596258117532452589460127027942070164795662430288688224914942555303");

    var result = Hex.hex(i);

    var expected = "a5e930f5d34c7e4d510dc158b2db4f062549d061dc5188714c980031fbf974a7";
    assertEquals(expected, result);
  }

  @Test
  public void testUnhexBigInteger() {
    var i = Hex.unhexBigInteger("00a5e930f5d34c7e4d510dc158b2db4f062549d061dc5188714c980031fbf974a7");

    var expected = new BigInteger("75043633293596258117532452589460127027942070164795662430288688224914942555303");

    assertEquals(expected, i);
  }

  @Test
  public void testBigIntegerToHex() {
    assertEquals("-8000000000000000", hex(BigInteger.valueOf(Long.MIN_VALUE)));
    assertEquals("-8000000000000000", hex(BigInteger.valueOf(Long.MIN_VALUE)));
    assertEquals("-1", hex(BigInteger.valueOf(-1)));
    assertEquals("0", hex(BigInteger.ZERO));
    assertEquals("1", hex(BigInteger.ONE));
    assertEquals("2", hex(BigInteger.TWO));
    assertEquals("a", hex(BigInteger.valueOf(10)));
    assertEquals("10", hex(BigInteger.valueOf(16)));
    assertEquals("7fffffffffffffff", hex(BigInteger.valueOf(Long.MAX_VALUE)));
    assertEquals("8000000000000000", hex(BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE)));
  }

  @Test
  public void testHexToBigInteger() {
    assertEquals(BigInteger.valueOf(Long.MIN_VALUE), unhexBigInteger("-8000000000000000"));
    assertEquals(BigInteger.valueOf(-1), unhexBigInteger("-1"));
    assertEquals(BigInteger.ZERO, unhexBigInteger("0"));
    assertEquals(BigInteger.ONE, unhexBigInteger("1"));
    assertEquals(BigInteger.TWO, unhexBigInteger("2"));
    assertEquals(BigInteger.valueOf(10), unhexBigInteger("a"));
    assertEquals(BigInteger.valueOf(16), unhexBigInteger("10"));
    assertEquals(BigInteger.valueOf(Long.MAX_VALUE), unhexBigInteger("7fffffffffffffff"));
    assertEquals(BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE), unhexBigInteger("8000000000000000"));
  }

  @Test
  public void testLongToHex() {
    assertEquals("-8000000000000000", hexNoPad(Long.MIN_VALUE));
    assertEquals("-1", hexNoPad(-1));
    assertEquals("0", hexNoPad(0));
    assertEquals("1", hexNoPad(1));
    assertEquals("2", hexNoPad(2));
    assertEquals("a", hexNoPad(10));
    assertEquals("10", hexNoPad(16));
    assertEquals("7fffffffffffffff", hexNoPad(Long.MAX_VALUE));
  }

  @Test
  public void testHexToLong() {
    assertEquals(Long.MIN_VALUE, unhexLong("-8000000000000000"));
    assertEquals(-1, unhexLong("-1"));
    assertEquals(0, unhexLong("0"));
    assertEquals(1, unhexLong("1"));
    assertEquals(1, unhexLong("1"));
    assertEquals(2, unhexLong("2"));
    assertEquals(10, unhexLong("a"));
    assertEquals(16, unhexLong("10"));
    assertEquals(Long.MAX_VALUE, unhexLong("7fffffffffffffff"));
  }

}
