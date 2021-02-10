package foundation.identity.keri.demo;

import foundation.identity.keri.controller.Controller;
import foundation.identity.keri.eventstorage.inmemory.InMemoryEventStore;
import foundation.identity.keri.keystorage.inmemory.InMemoryIdentifierKeyStore;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.List;

public class Bob {

  public static void main(String[] args) throws Exception {
    // enables secp256k1 -- TODO need to switch to bouncycastle for jdk16
    System.setProperty("jdk.sunec.disableNative", "false");

    var eventStore = new InMemoryEventStore();
    var keyStore = new InMemoryIdentifierKeyStore();
    var secureRandom = new SecureRandom(new byte[]{0});
    var controller = new Controller(eventStore, keyStore, secureRandom);
    var identifier = controller.newPrivateIdentifier();

    identifier.rotate();
    identifier.seal(List.of());

    var node = new DirectModeNode(identifier, eventStore)
        .connect(new InetSocketAddress("localhost", 5621))
        .block();

//    KeriClient.create()
//        .remoteAddress(() -> new InetSocketAddress("localhost", 5621))
//        .sendEvent(Flux.<Event> fromStream(eventStore.find(identifier.identifier())))
//        .handle((in, out) -> {
//          return in.receiveObject()
//              // process
//              .then();
//        })
//        .connectNow();

    // block until the server is disposed
    node.onDispose()
        .block();
  }

}
