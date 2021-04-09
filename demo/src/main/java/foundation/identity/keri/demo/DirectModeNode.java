package foundation.identity.keri.demo;

import foundation.identity.keri.KeyEventStore;
import foundation.identity.keri.KeyEventValidator;
import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.ReceiptEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferableIdentifierEvent;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.controller.ControllableIdentifier;
import foundation.identity.keri.controller.EventFactory;
import foundation.identity.keri.controller.spec.ReceiptFromTransferableIdentifierSpec;
import foundation.identity.keri.demo.protocol.EventInbound;
import foundation.identity.keri.demo.protocol.EventOutbound;
import foundation.identity.keri.demo.protocol.KeriClient;
import foundation.identity.keri.demo.protocol.KeriServer;
import io.netty.handler.logging.LogLevel;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.netty.Connection;
import reactor.netty.DisposableServer;
import reactor.netty.transport.logging.AdvancedByteBufFormat;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

public class DirectModeNode {

  private final ControllableIdentifier identifier;
  private final KeyEventStore keyEventStore;

  private final KeyEventValidator keyEventValidator;
  private final EventFactory eventFactory = new EventFactory();

  public DirectModeNode(ControllableIdentifier identifier, KeyEventStore keyEventStore) {
    this.identifier = identifier;
    this.keyEventStore = keyEventStore;
    this.keyEventValidator = new KeyEventValidator(keyEventStore);
  }

  public Mono<? extends DisposableServer> bind(InetSocketAddress address) {
    return KeriServer.create()
        .bindAddress(() -> address)
        .wiretap("keri-server", LogLevel.INFO, AdvancedByteBufFormat.TEXTUAL, StandardCharsets.UTF_8)
        .doOnBound(disposableServer
            -> System.out.println("[Node] LISTENING on " + disposableServer.channel().localAddress()))
        .doOnConnection(connection
            -> System.out.println("[Node] <<< CONNECT <<< " + connection.channel().remoteAddress()))
        .handle(this::handleEvents)
        .doOnUnbound(disposableServer
            -> System.out.println("[Node] STOPPED"))
        .bind();
  }

  public Mono<? extends Connection> connect(InetSocketAddress address) {
    return KeriClient.create()
        .remoteAddress(() -> address)
        .doOnConnect(c -> System.out.println("[Node] CONNECTING to " + address))
        .doOnConnected(c -> System.out.println("[Node] CONNECTED to " + address))
        .sendEvent(retrieveIdentifierEvents(address))
        .handle(this::handleEvents)
        .doOnDisconnected(c -> System.out.println("[Node] DISCONNECTED from " + address))
        .connect();
  }

  private Publisher<? extends Event> retrieveIdentifierEvents(InetSocketAddress address) {
    return Flux.fromStream(this.keyEventStore.streamKeyEvents(this.identifier.identifier()))
        .delayElements(Duration.ofMillis(250), Schedulers.single())
        .doOnNext(e-> {
          System.out.println("\n[Node] >>> EVENT >>> " + address);
          EventUtils.printEvent(e);
        });
  }

  private Publisher<Void> handleEvents(EventInbound in, EventOutbound out) {
    return in.receiveEvents()
        .doOnError(Throwable::printStackTrace)
        .doOnNext(e -> {
          System.out.println("\n[Node] <<< EVENT <<< " + ((Connection) in).channel().remoteAddress());
          EventUtils.printEvent(e);
        })
        .flatMap(e ->
            out.sendEvent(
              process(e)
                  .doOnError(Throwable::printStackTrace)
                .doOnNext(e2 -> {
                  System.out.println("\n[Node] >>> EVENT >>> " + ((Connection) in).channel().remoteAddress());
                  EventUtils.printEvent(e2);
                })
            )
            .then(),
            1);
  }

  private Flux<Event> process(Event event) {
    try {
      if (event instanceof KeyEvent) {
          var ie = (KeyEvent) event;
          // TODO these should all be reactive -- eventStore will eventually block!
          var state = getState(ie.identifier());
          this.keyEventValidator.validate(state, ie);
          this.keyEventStore.append(ie); // stator

          return produceChit(ie);
      }

      // TODO validate Receipt
      this.keyEventStore.append((ReceiptEvent) event);
      return Flux.empty();
    } catch (Exception e) {
      e.printStackTrace(System.err);
      return Flux.error(e);
    }
  }

  private Flux<Event> produceChit(KeyEvent ie) {
    var lastReceipt = this.keyEventStore.findLatestReceipt(this.identifier.identifier(), ie.identifier());
    var lastEventSequenceNumber = lastReceipt.isPresent()
                                  ? lastReceipt.get().event().sequenceNumber()
                                  : -1;
    var events = Flux.<Event> empty();
    if (lastEventSequenceNumber != this.identifier.lastEvent().sequenceNumber()) {
      // make sure we've sent our log so they can verify the chit
      System.out.println("[Node] WILL SEND LOG >>> ");
      events = produceOwnLog(lastEventSequenceNumber);
    }

    System.out.println("[Node] WILL SEND VRC >>> ");
    return Flux.concat(events, Mono.just(receiptEvent(ie)));
  }

  private Flux<Event> produceOwnLog(long fromSequenceNumber) {
    var events = this.keyEventStore
        .streamKeyEvents(this.identifier.identifier(), fromSequenceNumber + 1);

    return Flux.fromStream(events);
  }

  private KeyState getState(Identifier identifier) {
    return this.keyEventStore.getKeyState(identifier).orElse(null);
  }

  private ReceiptFromTransferableIdentifierEvent receiptEvent(KeyEvent event) {
    var receipt = this.identifier.sign(event);

    var spec = ReceiptFromTransferableIdentifierSpec.builder()
        .signature(receipt)
        .build();

    var rct = this.eventFactory.receipt(spec);
    this.keyEventStore.append(rct);
    return rct;
  }

}
