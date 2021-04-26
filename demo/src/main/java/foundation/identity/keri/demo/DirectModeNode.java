package foundation.identity.keri.demo;

import foundation.identity.keri.KeyEventStore;
import foundation.identity.keri.KeyEventValidator;
import foundation.identity.keri.KeyEvents;
import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.identifier.Identifier;
import foundation.identity.keri.controller.ControllableIdentifier;
import foundation.identity.keri.controller.EventFactory;
import foundation.identity.keri.demo.protocol.EventInbound;
import foundation.identity.keri.demo.protocol.EventOutbound;
import foundation.identity.keri.demo.protocol.KeriClient;
import foundation.identity.keri.demo.protocol.KeriServer;
import foundation.identity.keri.internal.event.ImmutableAttachmentEvent;
import io.netty.handler.logging.LogLevel;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.netty.Connection;
import reactor.netty.DisposableServer;
import reactor.netty.transport.logging.AdvancedByteBufFormat;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

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
        .sendEvent(this.retrieveIdentifierEvents(address))
        .handle(this::handleEvents)
        .doOnDisconnected(c -> System.out.println("[Node] DISCONNECTED from " + address))
        .connect();
  }

  private Publisher<? extends KeyEvent> retrieveIdentifierEvents(InetSocketAddress address) {
    return Flux.fromStream(this.keyEventStore.streamKeyEvents(this.identifier.identifier()))
        .delayElements(Duration.ofMillis(250), Schedulers.single())
        .doOnNext(e-> {
          System.out.println("\n[Node] >>> EVENT >>> " + address);
          KeyEvents.toString(e);
        });
  }

  private Publisher<Void> handleEvents(EventInbound in, EventOutbound out) {
    return in.receiveEvents()
        .doOnError(Throwable::printStackTrace)
        .doOnNext(e -> {
          System.out.println("\n[Node] <<< EVENT <<< " + ((Connection) in).channel().remoteAddress());
          KeyEvents.toString(e);
        })
        .flatMap(e ->
            out.sendEvent(
                this.process(e)
                  .doOnError(Throwable::printStackTrace)
                .doOnNext(e2 -> {
                  System.out.println("\n[Node] >>> EVENT >>> " + ((Connection) in).channel().remoteAddress());
                  KeyEvents.toString(e2);
                })
            )
            .then(),
            1);
  }

  private Flux<KeyEvent> process(KeyEvent event) {
    try {
      if (event instanceof AttachmentEvent) {
        this.keyEventStore.append((AttachmentEvent) event);
        return Flux.empty();
      }

      // TODO these should all be reactive -- eventStore will eventually block!
      var state = this.getState(event.identifier());
      this.keyEventValidator.validate(state, event);
      this.keyEventStore.append(event); // stator
      return this.produceChit(event);
    } catch (Exception e) {
      e.printStackTrace(System.err);
      return Flux.error(e);
    }
  }

  private Flux<KeyEvent> produceChit(KeyEvent keyEvent) {
    var events = Flux.<KeyEvent> empty();
    long lastEventSequenceNumber = this.keyEventStore.findLatestReceipt(this.identifier.identifier(), keyEvent.identifier())
        .orElse(-1L);

    if (lastEventSequenceNumber < this.identifier.lastEvent().sequenceNumber()) {
      // make sure we've sent our log so they can verify the chit
      System.out.println("[Node] WILL SEND LOG >>> ");
      events = this.produceOwnLog(lastEventSequenceNumber);
    }

    System.out.println("[Node] WILL SEND VRC >>> ");
//    return Flux.concat(events, Mono.just(this.receiptEvent(keyEvent)));
    // FIXME broke
    return Flux.empty();
  }

  private Flux<KeyEvent> produceOwnLog(long fromSequenceNumber) {
    var events = this.keyEventStore
        .streamKeyEvents(this.identifier.identifier(), fromSequenceNumber + 1);

    return Flux.fromStream(events);
  }

  private KeyState getState(Identifier identifier) {
    return this.keyEventStore.getKeyState(identifier).orElse(null);
  }

  private AttachmentEvent receiptEvent(KeyEvent event) {
    var receipt = this.identifier.sign(event);

    var rct = new ImmutableAttachmentEvent(
        event.coordinates(), Map.of(), Map.of(), Map.of(receipt.keyEstablishmentEvent(), receipt.signatures()));
    this.keyEventStore.append(rct);
    return rct;
  }

}
