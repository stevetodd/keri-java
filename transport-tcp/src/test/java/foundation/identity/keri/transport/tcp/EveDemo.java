package foundation.identity.keri.transport.tcp;

import foundation.identity.keri.KeyEventProcessor;
import foundation.identity.keri.controller.Controller;
import foundation.identity.keri.eventstorage.inmemory.InMemoryKeyEventEscrow;
import foundation.identity.keri.eventstorage.inmemory.InMemoryKeyEventStore;
import foundation.identity.keri.keystorage.inmemory.InMemoryIdentifierKeyStore;
import io.netty.util.internal.logging.InternalLoggerFactory;
import io.netty.util.internal.logging.Slf4JLoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.security.SecureRandom;

public class EveDemo {

  private static final Logger LOGGER = LoggerFactory.getLogger(EveDemo.class);

  public static void main(String[] args) throws InterruptedException {
    // enables secp256k1 -- TODO need to switch to bouncycastle for jdk16
    System.setProperty("jdk.sunec.disableNative", "false");
    InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE);

    LOGGER.info("Starting Eve demo...");

    // processor
    var secureRandom = new SecureRandom(new byte[]{0});
    var keyStore = new InMemoryIdentifierKeyStore();
    var keyEventStore = new InMemoryKeyEventStore();
    var keyEventEscrow = new InMemoryKeyEventEscrow();

    // controller
    var controller = new Controller(keyEventStore, keyStore, secureRandom);
    var identifier = controller.newPrivateIdentifier();

    // TODO node behaviors wrapped around processor? Direct, Witness, Watcher, Validator, etc.?

    // XXX processor validates and stores.
    // processor for each role wrapped around own stored event log?

    var processor = new KeyEventProcessor(keyEventStore, keyEventEscrow);

    var server = new TCPServer(processor);
    var f = server.bind(new InetSocketAddress("127.0.0.1", 5621));
    f.channel().closeFuture().sync();

    LOGGER.info("Eve demo completed.");
  }

}
