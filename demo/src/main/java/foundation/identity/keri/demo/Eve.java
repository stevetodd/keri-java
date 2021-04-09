package foundation.identity.keri.demo;

import foundation.identity.keri.controller.Controller;
import foundation.identity.keri.eventstorage.inmemory.InMemoryKeyEventStore;
import foundation.identity.keri.keystorage.inmemory.InMemoryIdentifierKeyStore;

import java.net.InetSocketAddress;
import java.security.SecureRandom;

public class Eve {

  public static void main(String[] args) {
    // enables secp256k1 -- TODO need to switch to bouncycastle for jdk16
    System.setProperty("jdk.sunec.disableNative", "false");

    var keyEventStore = new InMemoryKeyEventStore();
    var keyStore = new InMemoryIdentifierKeyStore();
    var secureRandom = new SecureRandom(new byte[]{0});
    var controller = new Controller(keyEventStore, keyStore, secureRandom);
    var identifier = controller.newPrivateIdentifier();

    var node = new DirectModeNode(identifier, keyEventStore)
        .bind(new InetSocketAddress("localhost", 5621))
        .block();

    // block until the server is disposed
    node.onDispose()
        .block();
  }

}
