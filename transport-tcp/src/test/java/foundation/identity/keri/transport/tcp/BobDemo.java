package foundation.identity.keri.transport.tcp;

import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.controller.Controller;
import foundation.identity.keri.eventstorage.inmemory.InMemoryKeyEventStore;
import foundation.identity.keri.keystorage.inmemory.InMemoryIdentifierKeyStore;
import io.netty.channel.Channel;
import io.netty.util.internal.logging.InternalLoggerFactory;
import io.netty.util.internal.logging.Slf4JLoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static foundation.identity.keri.ShortQualifiedBase64.shortQb64;
import static java.util.Comparator.comparingLong;

public class BobDemo {

  private static final Logger LOGGER = LoggerFactory.getLogger(BobDemo.class);

  public static void main(String[] args) throws InterruptedException, NoSuchAlgorithmException {
    // enables secp256k1 -- TODO [jdk16] switch to bouncycastle
    System.setProperty("jdk.sunec.disableNative", "false");
    InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE);

    LOGGER.info("Starting Bob demo...");

    // get a predictable identifier
    var secureRandom = SecureRandom.getInstance("SHA1PRNG");
    secureRandom.setSeed(new byte[]{1});

    var keyStore = new InMemoryIdentifierKeyStore();
    var keyEventStore = new InMemoryKeyEventStore();

    // controller
    var controller = new Controller(keyEventStore, keyStore, secureRandom);
    var identifier = controller.newPrivateIdentifier();

    LOGGER.info(">> Bob's Identifier: {}", identifier.identifier());

    DirectMode.listen(identifier, keyEventStore, new InetSocketAddress("127.0.0.1", 5620));

    Channel client;
    while (true) {
      var channelFuture = DirectMode.connect(
          identifier,
          keyEventStore,
          new InetSocketAddress("127.0.0.1", 5621));
      channelFuture.awaitUninterruptibly();
      if (channelFuture.isSuccess()) {
        client = channelFuture.channel();
        break;
      }
      Thread.sleep(TimeUnit.SECONDS.toMillis(1));
    }

    sendLastEvent(client, identifier.lastEvent());

    Thread.sleep(TimeUnit.SECONDS.toMillis(1));

    identifier.rotate();
    sendLastEvent(client, identifier.lastEvent());

    Thread.sleep(TimeUnit.SECONDS.toMillis(1));

    identifier.seal(List.of());
    sendLastEvent(client, identifier.lastEvent());

    Thread.sleep(TimeUnit.SECONDS.toMillis(1));

    LOGGER.info("(sending reversed events)");

    identifier.rotate();
    identifier.rotate();
    identifier.rotate();
    identifier.seal(List.of());
    identifier.rotate();
    identifier.rotate();
    identifier.seal(List.of());
    identifier.rotate();
    identifier.rotate();
    identifier.rotate();
    identifier.seal(List.of());

    keyEventStore.streamKeyEvents(identifier.identifier(), 3)
        .sorted(comparingLong(KeyEvent::sequenceNumber).reversed())
        .forEachOrdered(ke -> {
          LOGGER.info("SEND: {}", shortQb64(ke.coordinates()));
          client.writeAndFlush(ke);
          client.read();
        });

    Thread.sleep(TimeUnit.SECONDS.toMillis(10));

    client.close().sync();

    LOGGER.info("Bob demo completed.");
  }

  private static void sendLastEvent(Channel client, KeyEvent e) {
    LOGGER.info("SEND: {}", shortQb64(e.coordinates()));
    client.writeAndFlush(e).awaitUninterruptibly();
    client.read();
  }

}
