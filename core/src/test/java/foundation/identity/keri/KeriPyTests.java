package foundation.identity.keri;

import foundation.identity.keri.crypto.SignatureOperations;
import org.junit.BeforeClass;
import org.junit.Test;

import static foundation.identity.keri.Hex.unhex;

public class KeriPyTests {

  @BeforeClass
  public static void beforeClass() {
    // secp256k1 is considered "unsecure" so you have enable it like this:
    System.setProperty("jdk.sunec.disableNative", "false");
  }

  @Test
  public void test_keyeventfuncs() {
    final var privateKeyBytes = unhex("9f7ba8a7a843399626fab199ebaa20c41b4711c4ae534152c9bd049d85297e93");
    final var publicKeyBytes = unhex("5b3c041c7ceaecad20cd03d8186c139aeba95213f1e7fc99f96935c787a385c7");
    final var privateKey = SignatureOperations.ED_25519.privateKey(privateKeyBytes);
    final var publicKey = SignatureOperations.ED_25519.publicKey(publicKeyBytes);

//  # Inception: Non-transferable (ephemeral) case
//  signer0 = Signer(raw=seed, transferable=False)  #  original signing keypair non transferable
//  assert signer0.code == CryOneDex.Ed25519_Seed
//  assert signer0.verfer.code == CryOneDex.Ed25519N
//  keys0 = [signer0.verfer.qb64]
//  serder = incept(keys=keys0)  #  default nxt is empty so abandoned
//  assert serder.ked["pre"] == 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
//  assert serder.ked["nxt"] == ""
//  assert serder.raw == (b'{"vs":"KERI10JSON0000cf_","pre":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
//                        b'c","sn":"0","ilk":"icp","sith":"1","keys":["BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_y'
//                        b'Z-Wk1x4ejhcc"],"nxt":"","toad":"0","wits":[],"cnfg":[]}')

//    var controller = new Controller();
//    var i = controller.newBasicIdentifier(publicKey);
//    assertTrue(i.prefix() instanceof BasicPrefix);
//    assertArrayEquals(publicKey.getEncoded(), ((BasicPrefix) i.prefix()).publicKey().getEncoded());
//    assertEquals(1, i.signingThreshold());

  }

}
