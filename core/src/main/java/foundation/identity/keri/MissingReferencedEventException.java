package foundation.identity.keri;

import foundation.identity.keri.api.event.AttachmentEvent;
import foundation.identity.keri.api.event.KeyEventCoordinates;

import static java.util.Objects.requireNonNull;

public class MissingReferencedEventException extends AttachmentEventProcessingException {

  private final KeyEventCoordinates referencedEvent;

  public MissingReferencedEventException(AttachmentEvent attachmentEvent, KeyEventCoordinates referencedEvent) {
    super(attachmentEvent);
    this.referencedEvent = requireNonNull(referencedEvent);
  }

  public KeyEventCoordinates referencedEvent() {
    return this.referencedEvent;
  }

}
