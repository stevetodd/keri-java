package foundation.identity.keri.controller;

public class IdentifierFactoryTests {
/*
  final static ObjectMapper MAPPER = new ObjectMapper();

  @BeforeClass
  public static void beforeClass() {
    // secp256k1 is considered "insecure" so you have enable it like this:
    System.setProperty("jdk.sunec.disableNative", "false");
  }

  private List<KeyPair> generateKeys(int count, SignatureAlgorithm algorithm) {
    var keys = new KeyPair[count];

    for (var i = 0; i < count; i++) {
      keys[i] = generateKey(algorithm);
    }

    return Arrays.asList(keys);
  }

  private KeyPair generateKey(SignatureAlgorithm algorithm) {
    var stdAlgo = StandardSignatureAlgorithms.valueOf(algorithm);
    return switch (stdAlgo) {
      case EC_SECP256K1 -> SignatureOperations.EC_SECP256K1.generateKeyPair();
      case ED_25519 -> SignatureOperations.ED_25519.generateKeyPair();
      case ED_448 -> SignatureOperations.ED_448.generateKeyPair();
      default -> throw new RuntimeException(
          "Unknown algorithm: " + algorithm);
    };
  }

  @Test
  public void test__newBasicIdentifier__ED_25519__KeyPair() {
    var keyPair = generateKey(ED_25519);
    var i = IdentifierFactory.newBasicIdentifier(keyPair);

    assertTrue(i.identifier() instanceof BasicPrefix);
    assertArrayEquals(i.keys().get(0).getEncoded(), ((BasicPrefix) i.identifier()).publicKey().getEncoded());

    assertEquals(1, i.signingThreshold());
    assertEquals(1, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());
  }

  @Test
  public void test__newBasicIdentifier__ED_25519__PublicKey() {
    var keyPair = generateKey(ED_25519);
    var i = IdentifierFactory.newBasicIdentifier(keyPair.getPublic());

    assertTrue(i.identifier() instanceof BasicPrefix);
    assertArrayEquals(i.keys().get(0).getEncoded(), ((BasicPrefix) i.identifier()).publicKey().getEncoded());

    assertEquals(1, i.signingThreshold());
    assertEquals(1, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());
  }

  @Test
  public void test__newBasicIdentifier__EC_SECP256K1__KeyPair() {
    var keyPair = generateKey(EC_SECP256K1);
    var i = IdentifierFactory.newBasicIdentifier(keyPair);

    assertTrue(i.identifier() instanceof BasicPrefix);
    assertArrayEquals(i.keys().get(0).getEncoded(), ((BasicPrefix) i.identifier()).publicKey().getEncoded());

    assertEquals(1, i.signingThreshold());
    assertEquals(1, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());
  }

  @Test
  public void test__newBasicIdentifier__ED_448__KeyPair() {
    var keyPair = generateKey(ED_448);
    var i = IdentifierFactory.newBasicIdentifier(keyPair);

    assertTrue(i.identifier() instanceof BasicPrefix);
    assertArrayEquals(i.keys().get(0).getEncoded(), ((BasicPrefix) i.identifier()).publicKey().getEncoded());

    assertEquals(1, i.signingThreshold());
    assertEquals(1, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());
  }

  @Test
  public void test__newBasicIdentifier__ED_448__PublicKey() {
    var keyPair = generateKey(ED_448);
    var i = IdentifierFactory.newBasicIdentifier(keyPair.getPublic());

    assertTrue(i.identifier() instanceof BasicPrefix);
    assertArrayEquals(i.keys().get(0).getEncoded(), ((BasicPrefix) i.identifier()).publicKey().getEncoded());

    assertEquals(1, i.signingThreshold());
    assertEquals(1, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());
  }

  @Test
  public void test__newIdentifier__ED_25519__KeyPair() {
    var keyPair = generateKey(ED_25519);
    var i = IdentifierFactory.newIdentifier(keyPair);

    assertTrue(i.identifier() instanceof SelfAddressingPrefix);
    assertEquals(StandardDigestAlgorithms.BLAKE3_256, ((SelfAddressingPrefix) i.identifier()).digest().algorithm());

    assertEquals(1, i.signingThreshold());
    assertEquals(1, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());
  }

  @Test
  public void test__newIdentifier__ED_448__KeyPair() {
    var keyPair = generateKey(ED_448);
    var i = IdentifierFactory.newIdentifier(keyPair);

    assertTrue(i.identifier() instanceof SelfAddressingPrefix);
    assertEquals(StandardDigestAlgorithms.BLAKE3_256, ((SelfAddressingPrefix) i.identifier()).digest().algorithm());

    assertEquals(1, i.signingThreshold());
    assertEquals(1, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());
  }

  @Test
  public void test__newIdentifier__EC_SECP256K1__KeyPair() {
    var keyPair = generateKey(EC_SECP256K1);
    var i = IdentifierFactory.newIdentifier(keyPair);

    assertTrue(i.identifier() instanceof SelfAddressingPrefix);
    assertEquals(StandardDigestAlgorithms.BLAKE3_256, ((SelfAddressingPrefix) i.identifier()).digest().algorithm());

    assertEquals(1, i.signingThreshold());
    assertEquals(1, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());
  }

  @Test
  public void test__newIdentifier__ED_25519__MultipleKeyPair() {
    var keyPairs = generateKeys(6, ED_25519);

    var spec = IdentifierSpec.builder()
        .selfAddressing(StandardDigestAlgorithms.BLAKE3_256)
        .keys(keyPairs.stream().map(KeyPair::getPublic).collect(toList()))
        .build();

    var i = IdentifierFactory.newIdentifier(spec);

    assertTrue(i.identifier() instanceof SelfAddressingPrefix);
    assertEquals(StandardDigestAlgorithms.BLAKE3_256, ((SelfAddressingPrefix) i.identifier()).digest().algorithm());

    assertEquals(4, i.signingThreshold());
    assertEquals(6, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());
  }

  @Test
  public void test__newSelfSignedIdentifier__ED_25519__KeyPair() throws IOException {
    var keyPair = generateKey(ED_25519);
    var i = IdentifierFactory.newSelfSignedIdentifier(keyPair);

    assertTrue(i.identifier() instanceof SelfSigningPrefix);
    assertEquals(StandardSignatureAlgorithms.ED_25519, ((SelfSigningPrefix) i.identifier()).signature().algorithm());
    // validate signature

    assertEquals(1, i.signingThreshold());
    assertEquals(1, i.keys().size());

    assertEquals(0, i.witnessThreshold());
    assertEquals(0, i.witnesses().size());

    assertEquals(EnumSet.noneOf(ConfigurationTrait.class), i.configurationTraits());

    var json = MAPPER.readTree(i.events().findFirst().get().bytes());

    var jsonIterator = json.fields();
    for (var fieldName : EventFieldNames.INCEPTION_FIELDS) {
      assertEquals(fieldName.label(), jsonIterator.next().getKey());
    }
    assertEquals(EventFieldNames.INCEPTION_FIELDS.size(), json.size());

    assertEquals("KERI10JSON0000e6_", json.get(EventFieldNames.VERSION.label()).textValue());
    // assertEquals("",
    // json.get(EventFieldNames.IDENTIFIER_PREFIX.label()).textValue());
    var prefix = json.get(EventFieldNames.IDENTIFIER_PREFIX.label()).textValue();
    assertEquals("0B", prefix.substring(0, 2));
    assertEquals(88, prefix.length());
    assertEquals("0", json.get(EventFieldNames.SEQUENCE_NUMBER.label()).textValue());
    assertEquals("icp", json.get(EventFieldNames.EVENT_TYPE.label()).textValue());
    assertEquals("1", json.get(EventFieldNames.SIGNING_THRESHOLD.label()).textValue());
    assertTrue("Expected key list to be an array.", json.get(EventFieldNames.KEYS.label()).isArray());
    assertEquals(1, json.get(EventFieldNames.KEYS.label()).size());

    var key = json.get(EventFieldNames.KEYS.label()).get(0).textValue();
    assertEquals("D", key.substring(0, 1));
    assertEquals(44, key.length());

    assertEquals("", json.get(EventFieldNames.NEXT_KEYS_DIGEST.label()).textValue());

//    var nextKeys = json.get(EventFieldNames.NEXT_KEYS_DIGEST.label()).textValue();
//    assertEquals("", nextKeys.substring(0, 10));
//    assertEquals(0, nextKeys.length());

    assertEquals("0", json.get(EventFieldNames.WITNESS_THRESHOLD.label()).textValue());
    assertTrue("Expected witness list to be an array.", json.get(EventFieldNames.WITNESSES.label()).isArray());
    assertTrue("Expected witness list to be empty.", json.get(EventFieldNames.WITNESSES.label()).isEmpty());
    assertTrue("Expected configuration to be an array.", json.get(EventFieldNames.CONFIGURATION.label()).isArray());
    assertTrue("Expected configuration to be empty.", json.get(EventFieldNames.CONFIGURATION.label()).isEmpty());

    // TODO validate generated event

//    {
//      "v"   : "KERI10JSON00011c_",
//      "i"  : "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
//      "t"  : "ksn",
//      "kt" : "1",
//      "k" : ["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],
//      "n"  : "EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
//      "wt" : "1",
//      "w" : ["DnmwyYAfSVPzhzS6b5CMZ-i0d8JZAoTNZH3ULvaU6JR2"],
//      "c" : ["eo"],
//      "e":
//            {
//                "s": "0",
//                "t": "rot",
//                "d" :  "EAoTNZH3ULvaU6JR2nmwyYAfSVPzhzZ-i0d8JZS6b5CM",
//            },
//      "ee" :
//             {
//               "s":  "1",
//               "d":  "EAoTNZH3ULvaU6JR2nmwyYAfSVPzhzZ-i0d8JZS6b5CM"
//              },
//      "di": ""
//    }
//
//    {
//      "v"  : "KERI10JSON00011c_",
//      "i"  : "AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
//      "s"  : "0",
//      "t"  : "icp",
//      "kt" : "1",
//      "k"  : ["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],
//      "n"  : "DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
//      "wt" : "1",
//      "w" : [],
//      "c" : []
//    }
  }
*/
}
