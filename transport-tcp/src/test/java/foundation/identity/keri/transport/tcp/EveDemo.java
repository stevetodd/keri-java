package foundation.identity.keri.transport.tcp;

import foundation.identity.keri.controller.Controller;
import foundation.identity.keri.eventstorage.inmemory.InMemoryKeyEventStore;
import foundation.identity.keri.keystorage.inmemory.InMemoryIdentifierKeyStore;
import io.netty.util.internal.logging.InternalLoggerFactory;
import io.netty.util.internal.logging.Slf4JLoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class EveDemo {

  private static final Logger LOGGER = LoggerFactory.getLogger(EveDemo.class);

  public static void main(String[] args) throws InterruptedException, NoSuchAlgorithmException {
    // enables secp256k1 -- TODO [jdk16] switch to bouncycastle
    System.setProperty("jdk.sunec.disableNative", "false");
    InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE);

    LOGGER.info("Starting Eve demo...");

    // get a predictable identifier
    var secureRandom = SecureRandom.getInstance("SHA1PRNG");
    secureRandom.setSeed(new byte[]{0});

    var keyStore = new InMemoryIdentifierKeyStore();
    var keyEventStore = new InMemoryKeyEventStore();

    // controller
    var controller = new Controller(keyEventStore, keyStore, secureRandom);
    var identifier = controller.newPrivateIdentifier();

    LOGGER.info(">> Eve's Identifier: {}", identifier.identifier());

    // TODO node behaviors wrapped around processor? Direct, Witness, Watcher, Validator, etc.?

    var server = DirectMode.listen(identifier, keyEventStore, new InetSocketAddress("127.0.0.1", 5621));
    server.channel().closeFuture().sync();

    LOGGER.info("Eve demo completed.");
  }

}
