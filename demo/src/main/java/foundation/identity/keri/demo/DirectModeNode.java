package foundation.identity.keri.demo;

import foundation.identity.keri.EventProcessor;
import foundation.identity.keri.EventStore;
import foundation.identity.keri.EventValidationException;
import foundation.identity.keri.EventValidator;
import foundation.identity.keri.api.IdentifierState;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.IdentifierEvent;
import foundation.identity.keri.api.event.ReceiptEvent;
import foundation.identity.keri.api.event.ReceiptFromTransferableIdentifierEvent;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.controller.ControllableIdentifier;
import foundation.identity.keri.controller.EventFactory;
import foundation.identity.keri.controller.spec.ReceiptFromTransferableIdentifierSpec;
import foundation.identity.keri.demo.protocol.EventInbound;
import foundation.identity.keri.demo.protocol.EventOutbound;
import foundation.identity.keri.demo.protocol.KeriChannelOperations;
import foundation.identity.keri.demo.protocol.KeriClient;
import foundation.identity.keri.demo.protocol.KeriServer;
import foundation.identity.keri.eventstorage.inmemory.InMemoryEventStore;
import foundation.identity.keri.internal.event.ImmutableEventSignature;
import io.netty.handler.logging.LogLevel;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;
import reactor.netty.DisposableServer;
import reactor.netty.transport.logging.AdvancedByteBufFormat;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class DirectModeNode {

  private final ControllableIdentifier identifier;
  private final EventStore eventStore;

  private final EventValidator eventValidator = new EventValidator();
  private final EventFactory eventFactory = new EventFactory();
  private final EventProcessor eventProcessor = new EventProcessor();

  private int port; // FIXME -- breaks if bind is called more than once

//  private final KeriClient client = KeriClient.create(
//          ConnectionProvider.builder("keri-client-receipts")
//              .maxConnections(1)
//              .pendingAcquireTimeout(Duration.ofSeconds(1))
//              .pendingAcquireMaxCount(100)
//              .maxIdleTime(Duration.ofSeconds(10))
//              .build())
//      .wiretap("keri-client", LogLevel.INFO, AdvancedByteBufFormat.TEXTUAL, StandardCharsets.UTF_8);

  public DirectModeNode(ControllableIdentifier identifier, EventStore eventStore) {
    this.identifier = identifier;
    this.eventStore = eventStore;
  }

  public Mono<? extends DisposableServer> bind(int port) {
    this.port = port;
    return KeriServer.create()
        .bindAddress(() -> new InetSocketAddress("127.0.0.1", port))
        .wiretap("keri-server", LogLevel.INFO, AdvancedByteBufFormat.TEXTUAL, StandardCharsets.UTF_8)
        .doOnBound(disposableServer -> {
          System.out.println("[KeriServer] STARTED on " + disposableServer.channel().localAddress());
        })
        .doOnConnection(connection -> {
          System.out.println("[KeriServer] <<< CONNECT <<< " + connection.channel().remoteAddress());
        })
        .handle(this::handleEvents)
        .doOnUnbound(disposableServer -> {
          System.out.println("[KeriServer] STOPPED");
        })
        .bind();
  }

  public Mono<? extends Connection> connect(InetSocketAddress address) {
    return KeriClient.create()
        .remoteAddress(() -> address)
        .doOnConnect(c -> System.out.println("[KeriClient] CONNECTING to " + address))
        .doOnConnected(c -> System.out.println("[KeriClient] CONNECTED to " + address))
        .doOnDisconnected(c -> System.out.println("[KeriClient] CONNECTED to " + address))
        .connect();
  }

  private Publisher<Void> handleEvents(EventInbound in, EventOutbound out) {
    return in.receiveEvents()
        .doOnNext(e -> {
          System.out.println("\n[KeriServer] <<< EVENT <<< " + ((Connection) in).channel().remoteAddress());
          EventUtils.printEvent(e);
        })
        .flatMap(e ->
            out.sendEvent(
              process(e)
                .doOnNext(e2 -> {
                  System.out.println("\n[KeriServer] >>> EVENT >>> " + ((Connection) in).channel().remoteAddress());
                  EventUtils.printEvent(e2);
                })
            )
            .then(),
            1);
//        .doOnNext(e -> {
//          System.out.println("\n[KeriServer] >>> EVENT >>> " + ((Connection) in).channel().remoteAddress());
//          EventUtils.printEvent(e);
//        });


//    return out.sendEvent(
//        in.receiveEvents()
//          .doOnNext(e -> {
//            System.out.println("\n[KeriServer] <<< EVENT <<< " + ((Connection) in).channel().remoteAddress());
//            EventUtils.printEvent(e);
//          })
//          .flatMap(this::process, 1)
//          .doOnNext(e -> {
//            System.out.println("\n[KeriServer] >>> EVENT >>> " + ((Connection) in).channel().remoteAddress());
//            EventUtils.printEvent(e);
//          })
//    );
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
      } else if (event instanceof ReceiptEvent) {
        var rct = (ReceiptEvent) event;
        //TODO this.eventValidator.validate(event);
        rct.receipts().stream()
            .forEach(this.eventStore::store);
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
      System.out.println("[KeriServer] WILL SEND LOG >>> ");
      events = produceOwnLog(lastEventSequenceNumber);
    }

    System.out.println("[KeriServer] WILL SEND VRC >>> ");
    return Flux.concat(events, Mono.just(receiptEvent(ie)));
  }

  private Flux<Event> produceOwnLog(BigInteger fromSequenceNumber) {
    var events = this.eventStore
        .find(this.identifier.identifier(), fromSequenceNumber.add(BigInteger.ONE));

    return Flux.fromStream(events);
  }

  /// ----
  private Mono<Void> processEvent(Event event, EventOutbound out) {
    if (event instanceof IdentifierEvent) {
      try {
        var ie = (IdentifierEvent) event;
        // TODO these should all be reactive -- eventStore will eventually block!
        var state = getState(ie.identifier());
        this.eventValidator.validate(state, ie);
        this.eventStore.store(ie); // stator

        return sendChitForEvent(ie, out);
      } catch (EventValidationException e) {
        System.err.println("Event is invalid: " + e.getMessage());
        return Mono.error(e);
      }
    } else if (event instanceof ReceiptFromTransferableIdentifierEvent) {
      // TODO verify
      // this.eventValidator.validate(null, re);
      //this.eventStore.store(((ReceiptFromTransferrableIdentifierEvent) event).receipt());
    }
    return null;
  }

  private IdentifierState getState(Identifier identifier) {
    var i = this.eventStore.find(identifier).iterator();

    IdentifierState state = null;
    while (i.hasNext()) {
      state = this.eventProcessor.apply(state, i.next());
    }

    return state;
  }

  private Mono<Void> sendChitForEvent(IdentifierEvent ie, EventOutbound out) {
    var lastReceipt = this.eventStore.findLatestReceipt(this.identifier.identifier(), ie.identifier());
    var lastEventSequenceNumber = lastReceipt.isPresent()
                                  ? lastReceipt.get().event().sequenceNumber()
                                  : BigInteger.valueOf(-1);
    var mono = Mono.<Void> empty();
    if (!lastEventSequenceNumber.equals(this.identifier.lastEvent().sequenceNumber())) {
      // make sure we've sent our log so they can verify the chit
      mono = sendOwnLog(lastEventSequenceNumber, out);
    }

    System.out.println("[KeriServer] SEND VRC >>> " + ((KeriChannelOperations) out).channel().remoteAddress());
    return Mono.zip(mono, sendEvent(Mono.just(receiptEvent(ie)), out)).then();
  }

  private ReceiptFromTransferableIdentifierEvent receiptEvent(IdentifierEvent event) {
    var receipt = this.identifier.sign(event);

    var spec = ReceiptFromTransferableIdentifierSpec.builder()
        .signature(receipt)
        .build();

    return this.eventFactory.receipt(spec);
  }

  private Mono<Void> sendOwnLog(BigInteger fromSequenceNumber, EventOutbound out) {
    System.out.println("[KeriServer] SEND OWN LOG >>> " + ((KeriChannelOperations) out).channel().remoteAddress());
    var events = this.eventStore
        .find(this.identifier.identifier(), fromSequenceNumber.add(BigInteger.ONE));

    return sendEvent(Flux.fromStream(events), out);
  }

  private Mono<Void> sendEvent(Publisher<Event> events, EventOutbound out) {
    return out.sendEvent(events).then();

     //KeriClient.create()
//    this.client
//        .remoteAddress(() -> this.resolveAddress(to))
//        //.wiretap("client", LogLevel.INFO)
//        .send(events)
//        .subscribe();

//        .sendEvent(Flux.from(events)
//            .doOnNext(e -> {
//              System.out.println("[KeriServer] >>> EVENT >>> " + ((Connection) out).channel().remoteAddress());
//              EventUtils.printEvent(e);
//            }))
//        .then()
//        .subscribe()
//        .dispose();
//
//    out.sendEvent(
//          Flux.from(events)
//            .doOnNext(e -> {
//              System.out.println("[KeriServer] >>> EVENT >>> " + ((Connection) out).channel().remoteAddress());
//              EventUtils.printEvent(e);
//            })
//        )
//        .then().subscribe();
  }

  private InetSocketAddress resolveAddress(Identifier identifier) {
    return new InetSocketAddress("localhost", this.port == 5621 ? 5620 : 5621);
  }

}
