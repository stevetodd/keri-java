package foundation.identity.keri;

import foundation.identity.keri.api.event.AttachmentEvent;

public class AttachmentEventProcessingException extends RuntimeException {

  private final AttachmentEvent attachmentEvent;

  public AttachmentEventProcessingException(AttachmentEvent attachmentEvent) {
    this.attachmentEvent = attachmentEvent;
  }

  public AttachmentEvent attachmentEvent() {
    return this.attachmentEvent;
  }

}
