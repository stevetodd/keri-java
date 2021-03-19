package foundation.identity.keri.demo;

import foundation.identity.keri.EventProcessor;
import foundation.identity.keri.EventStore;
import foundation.identity.keri.EventValidationException;
import foundation.identity.keri.EventValidator;
import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.ReceiptFromBasicIdentifierEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferableIdentifierEvent;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.controller.ControllableIdentifier;
import foundation.identity.keri.controller.EventFactory;
import foundation.identity.keri.controller.spec.ReceiptFromTransferableIdentifierSpec;
import foundation.identity.keri.demo.protocol.EventInbound;
import foundation.identity.keri.demo.protocol.EventOutbound;
import foundation.identity.keri.demo.protocol.KeriClient;
import foundation.identity.keri.demo.protocol.KeriServer;
import foundation.identity.keri.internal.event.ImmutableEventSignature;
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
  private final EventStore eventStore;

  private final EventValidator eventValidator = new EventValidator();
  private final EventFactory eventFactory = new EventFactory();
  private final EventProcessor eventProcessor = new EventProcessor();

  public DirectModeNode(ControllableIdentifier identifier, EventStore eventStore) {
    this.identifier = identifier;
    this.eventStore = eventStore;
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
    return Flux.fromStream(this.eventStore.find(this.identifier.identifier()))
        .delayElements(Duration.ofMillis(250), Schedulers.single())
        .doOnNext(e-> {
          System.out.println("\n[Node] >>> EVENT >>> " + address);
          EventUtils.printEvent(e);
        });
  }

  private Publisher<Void> handleEvents(EventInbound in, EventOutbound out) {
    return in.receiveEvents()
        .doOnNext(e -> {
          System.out.println("\n[Node] <<< EVENT <<< " + ((Connection) in).channel().remoteAddress());
          EventUtils.printEvent(e);
        })
        .flatMap(e ->
            out.sendEvent(
              process(e)
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
      if (event instanceof IdentifierEvent) {
          var ie = (IdentifierEvent) event;
          // TODO these should all be reactive -- eventStore will eventually block!
          var state = getState(ie.identifier());
          this.eventValidator.validate(state, ie);
          this.eventStore.store(ie); // stator

          return produceChit(ie);
      } else if (event instanceof ReceiptFromTransferableIdentifierEvent) {
        var vrc = (ReceiptFromTransferableIdentifierEvent) event;
        //TODO this.eventValidator.validate(event);
        vrc.signatures().stream()
            .map(as -> ImmutableEventSignature.from(as, vrc.keyEstablishmentEvent()))
            .forEach(this.eventStore::store);
      } else if (event instanceof ReceiptFromBasicIdentifierEvent) {
        var rct = (ReceiptFromBasicIdentifierEvent) event;
        //TODO this.eventValidator.validate(event);
        rct.receipts().forEach(this.eventStore::store);
      }
      return Flux.empty();
    } catch (EventValidationException e) {
      e.printStackTrace(System.err);
      return Flux.error(e);
    }
  }

  private Flux<Event> produceChit(IdentifierEvent ie) {
    var lastReceipt = this.eventStore.findLatestReceipt(this.identifier.identifier(), ie.identifier());
    var lastEventSequenceNumber = lastReceipt.isPresent()
                                  ? lastReceipt.get().event().sequenceNumber()
                                  : BigInteger.valueOf(-1);
    var events = Flux.<Event> empty();
    if (!lastEventSequenceNumber.equals(this.identifier.lastEvent().sequenceNumber())) {
      // make sure we've sent our log so they can verify the chit
      System.out.println("[Node] WILL SEND LOG >>> ");
      events = produceOwnLog(lastEventSequenceNumber);
    }

    System.out.println("[Node] WILL SEND VRC >>> ");
    return Flux.concat(events, Mono.just(receiptEvent(ie)));
  }

  private Flux<Event> produceOwnLog(BigInteger fromSequenceNumber) {
    var events = this.eventStore
        .find(this.identifier.identifier(), fromSequenceNumber.add(BigInteger.ONE));

    return Flux.fromStream(events);
  }

  private IdentifierState getState(Identifier identifier) {
    var i = this.eventStore.find(identifier).iterator();

    IdentifierState state = null;
    while (i.hasNext()) {
      state = this.eventProcessor.apply(state, i.next());
    }

    return state;
  }

  private ReceiptFromTransferableIdentifierEvent receiptEvent(IdentifierEvent event) {
    var receipt = this.identifier.sign(event);

    var spec = ReceiptFromTransferableIdentifierSpec.builder()
        .signature(receipt)
        .build();

    this.eventStore.store(receipt);
    return this.eventFactory.receipt(spec);
  }

}
