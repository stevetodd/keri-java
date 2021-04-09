package foundation.identity.keri;

import foundation.identity.keri.api.KeyState;
import foundation.identity.keri.api.event.DelegatingEventCoordinates;
import foundation.identity.keri.api.event.Event;
import foundation.identity.keri.api.event.KeyEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;
import foundation.identity.keri.api.event.InceptionEvent;
import foundation.identity.keri.api.event.ReceiptEvent;
import foundation.identity.keri.internal.event.ImmutableKeyEventCoordinates;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyEventProcessor {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeyEventProcessor.class);

  final KeyEventValidator validator;
  final KeyEventStore keyEventStore;
  final KeyEventEscrow escrow;

  public KeyEventProcessor(KeyEventStore keyEventStore, KeyEventEscrow escrow) {
    this.keyEventStore = keyEventStore;
    this.escrow = escrow;

    this.validator = new KeyEventValidator(keyEventStore);
  }

  public void process(Event event) {
    LOGGER.debug("PROCESS:\n{}", event);

    try {
      if (event instanceof KeyEvent) {
        processKeyEvent((KeyEvent) event);
        // see of arrival of event enables escrowed events to be processed
        processEscrow((KeyEvent) event);
      } else if (event instanceof ReceiptEvent) {
        processReceipt((ReceiptEvent) event);
      }

      // TODO promulgate to witnesses, watchers, etc.
    } catch (MissingEventException mee) {
      doOnMissingEvent(mee.missingEvent(), event);
    } catch (MissingDelegatingEventException mdee) {
      doOnMissingDelegatingEvent(mdee.missingEvent(), event);
    } catch (UnmetSigningThresholdException uste) {
      doOnUnmetSigningThreshold(event);
    } catch (UnmetWitnessThresholdException uwte) {
      doOnUnmetWitnessThreshold(event);
    } catch (InvalidKeyEventException eve) {
      doOnInvalidKeyEvent(event, eve);
    } catch (Exception e) {
      // unavailable storage or sources or memory?
      doOnError(event, e);
    }
  }

  private void processEscrow(KeyEvent event) {
    // TODO delegation
    var coords = ImmutableKeyEventCoordinates.of(event);
    escrow.eventsAwaiting(coords)
      .forEach(this::process);
  }

  private void doOnError(Event event, Exception e) {
    LOGGER.error("ERROR", e);
  }

  private void processKeyEvent(KeyEvent keyEvent) {
    KeyState state = null;
    if (!(keyEvent instanceof InceptionEvent)) {
      state = this.keyEventStore.getKeyState(keyEvent.previous())
          .orElseThrow(() -> new MissingEventException(keyEvent.previous(), keyEvent));
    }

    this.validator.validate(state, keyEvent);
    this.keyEventStore.append(keyEvent);
  }

  private void processReceipt(ReceiptEvent receiptEvent) {
    var event = this.keyEventStore.getKeyEvent(receiptEvent.event())
        .orElseThrow(() -> new MissingEventException(receiptEvent.event(), receiptEvent));

    // FIXME fix call to validate with null state
    this.validator.validate(null, receiptEvent);

    this.keyEventStore.append(receiptEvent);
  }

  protected void doOnMissingEvent(KeyEventCoordinates missingEvent,
      Event dependingEvent) {
    LOGGER.debug("MISSING EVENT: {}",  missingEvent);
    this.escrow.await(missingEvent, dependingEvent);
  }

  protected void doOnMissingDelegatingEvent(DelegatingEventCoordinates missingEvent,
      Event dependingEvent) {
    LOGGER.debug("MISSING DELEGATING EVENT: {}", missingEvent);
    this.escrow.await(missingEvent, dependingEvent);
  }

  protected void doOnInvalidKeyEvent(Event event, InvalidKeyEventException eve) {
    // drop
    LOGGER.debug("INVALID EVENT: {}", eve.getMessage());
  }

  protected void doOnUnmetSigningThreshold(Event event) {
    LOGGER.debug("UNMET SIGNATURE THRESHOLD");
    // this.escrow.awaitingControllerSignatures(event);
  }

  protected void doOnUnmetWitnessThreshold(Event event) {
    LOGGER.debug("UNMET WITNESS THRESHOLD");
    // this.escrow.awaitingWitnessReceipts(event);
  }

}
