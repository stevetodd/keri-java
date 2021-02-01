package foundation.identity.keri.demo;

import foundation.identity.keri.EventValidator;
import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferrableIdentifierEvent;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.controller.ControllableIdentifier;
import foundation.identity.keri.controller.Controller;
import foundation.identity.keri.controller.EventFactory;
import foundation.identity.keri.controller.spec.ReceiptFromTransferrableIdentifierSpec;
import foundation.identity.keri.demo.KeriServer.KeriServerConnection;
import foundation.identity.keri.eventstorage.inmemory.InMemoryEventStore;
import foundation.identity.keri.keystorage.inmemory.InMemoryIdentifierKeyStore;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.SynchronousSink;
import reactor.core.scheduler.Schedulers;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.Duration;

public class Eve {

  private final InMemoryEventStore eventStore = new InMemoryEventStore();
  private final InMemoryIdentifierKeyStore keyStore = new InMemoryIdentifierKeyStore();
  private final SecureRandom secureRandom = new SecureRandom(new byte[]{0});
  private final Controller controller = new Controller(eventStore, keyStore, secureRandom);

  private final ControllableIdentifier identifier = controller.newPrivateIdentifier();
  private final EventValidator eventValidator = new EventValidator();
  private final EventFactory eventFactory = new EventFactory();
  private Mono<KeriClient> other;

  public static void main(String[] args) throws Exception {
    // enables secp256k1 -- TODO need to switch to bouncycastle for jdk16
    System.setProperty("jdk.sunec.disableNative", "false");

    new Eve().run().block();
  }

  public Mono<Void> run() {
    this.eventStore.printContents();
    return KeriServer.bind(new InetSocketAddress("0.0.0.0", 5621), this::onConnection)
        .flatMap(s -> s.onDispose());
  }

  private Mono<Void> onConnection(KeriServerConnection c) {
    System.out.println("\n[SERVER] <<< CONNECTED <<< R:??????????(" + c.remoteAddress() + ")");
    c.receive()
        .delayElements(Duration.ofMillis(1000))
        .doOnNext(e -> {
          if (e instanceof IdentifierEvent) {
            System.out.println("\n[SERVER] <<< EVENT <<< R:" + id(((IdentifierEvent) e).identifier()) + "(" + c.remoteAddress() + ")");
          } else {
            System.out.println("\n[SERVER] <<< EVENT <<< R:??????????(" + c.remoteAddress() + ")");
          }

          EventUtils.printEvent(e);

          if (this.other == null && e instanceof IdentifierEvent) {
            this.other = this.connectClient(((IdentifierEvent) e).identifier()).cache();
          }
        })
        .handle(this::handleEvent)
        .doOnTerminate(() -> {
          //this.other.dispose(); // close client
          System.out.println("\n[SERVER] === DISCONNECTED === R:??????????(" + c.remoteAddress() + ")");
        })
        .subscribe();
    return Mono.never();
  }

  private void handleEvent(Event event, SynchronousSink<Void> next) {
    try {

      if (event instanceof IdentifierEvent) {
        var ie = (IdentifierEvent) event;

        var state = this.controller.getIdentifierState(ie.identifier());
        this.eventValidator.validate(state, (IdentifierEvent) event);
        System.out.println("--- VALID");
        this.eventStore.store(ie);
        System.out.println("--- STORED");

        var lastReceipt = this.eventStore.findLatestReceipt(this.identifier.identifier(), ie.identifier());

        System.out.println("lastReceipt: " + lastReceipt);
        var lastEventSequenceNumber = lastReceipt.isPresent()
                                      ? lastReceipt.get().event().sequenceNumber() : BigInteger.valueOf(-1);

        System.out.println("lastEventSequenceNumber: " + lastEventSequenceNumber);
        if (!lastEventSequenceNumber.equals(this.identifier.lastEvent().sequenceNumber())) {
          System.out.println("--- SEND OWN LOG");
          sendOwnLog(ie.identifier(), lastEventSequenceNumber);
        }

        System.out.println("--- SEND CHIT");
        //sendChitForEvent(ie);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void sendOwnLog(Identifier to, BigInteger fromSequenceNumber) {
    this.other.subscribe(c -> {
      c.send(
          Flux.fromStream(
              this.eventStore.find(
                  this.identifier.identifier(),
                  fromSequenceNumber.add(BigInteger.ONE))));
    });
  }

  private void sendChitForEvent(IdentifierEvent ie) {
    this.other.subscribe(c -> c.send(Flux.just(ie).map(this::receiptEvent)));
    //return connectClient(ie.identifier())
    // return this.other
    //   .flatMap(c -> {
    //     return c.send(
    //           Flux.just(ie)
    //             .map(this::receiptEvent)
    //             .doOnNext(e -> {
    //               System.out.println("\n[CLIENT] >>> RECEIPT >>> R:" + id(e.receipt().event().identifier()) + "(" + c.remoteAddress() + ")");
    //               EventUtils.printEvent(e);
    //             })
    //         );
    //   });
  }

  private Mono<KeriClient> connectClient(Identifier identifier) {
    var address = new InetSocketAddress("127.0.0.1", 5620);
    System.out.println("\n[CLIENT] >>> CONNECT >>> R:" + id(identifier) + "(" + address + ")");
    return KeriClient.connect(address)
        .publishOn(Schedulers.boundedElastic())
        .doOnSuccess(c -> {
          System.out.println("\n[CLIENT] >>> CONNECTED >>> R:" + id(identifier) + "(" + c.remoteAddress() + ")");
          c.onClose()
              .subscribe(v -> {
                System.out.println("\n[CLIENT] >>> DISCONNECTED >>> R:" + id(identifier) + "(" + c.remoteAddress() + ")");
              });
          // TODO register logging for close
        });
    // DISCONNECTED
  }

  private ReceiptFromTransferrableIdentifierEvent receiptEvent(IdentifierEvent event) {
    var receipt = identifier.sign(event);
    var spec = ReceiptFromTransferrableIdentifierSpec.builder()
        .receipt(receipt)
        .build();

    return eventFactory.receipt(spec);
  }

  private String id(Identifier identifier) {
    return identifier.toString().substring(0, 10);
  }

  private static class EventWithState {
    public IdentifierState state;
    public Event event;

    public EventWithState(IdentifierState state, Event event) {
      this.state = state;
      this.event = event;
    }
  }

}
