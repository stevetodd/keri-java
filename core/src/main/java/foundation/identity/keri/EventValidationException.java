package foundation.identity.keri;

import java.io.Serial;

public final class EventValidationException extends GeneralKeriException {
  @Serial
  private static final long serialVersionUID = 1L;

  public EventValidationException() {
    super();
  }

  public EventValidationException(String message) {
    super(message);
  }

  public EventValidationException(String message, Throwable cause) {
    super(message, cause);
  }

  public EventValidationException(Throwable cause) {
    super(cause);
  }

}
