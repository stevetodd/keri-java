package foundation.identity.keri.demo;

import foundation.identity.keri.controller.Controller;
import foundation.identity.keri.eventstorage.inmemory.InMemoryKeyEventStore;
import foundation.identity.keri.keystorage.inmemory.InMemoryIdentifierKeyStore;
import reactor.util.retry.Retry;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;

public class Bob {

  public static void main(String[] args) {
    // enables secp256k1 -- TODO need to switch to bouncycastle for jdk16
    System.setProperty("jdk.sunec.disableNative", "false");

    var keyEventStore = new InMemoryKeyEventStore();
    var keyStore = new InMemoryIdentifierKeyStore();
    var secureRandom = new SecureRandom(new byte[]{0});
    var controller = new Controller(keyEventStore, keyStore, secureRandom);
    var identifier = controller.newPrivateIdentifier();

    identifier.rotate();
    identifier.seal(List.of());

    new DirectModeNode(identifier, keyEventStore)
        .connect(new InetSocketAddress("localhost", 5621))
        .retryWhen(Retry.fixedDelay(Long.MAX_VALUE, Duration.ofSeconds(1)))
        .block()
        .onDispose()
        .block();
  }

}
