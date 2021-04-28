package foundation.identity.keri;

import java.io.Serial;

public class SerializationException extends GeneralKeriException {
  @Serial
  private static final long serialVersionUID = 1L;

  public SerializationException() {
    super();
  }

  public SerializationException(String message) {
    super(message);
  }

  public SerializationException(String message, Throwable cause) {
    super(message, cause);
  }

  public SerializationException(Throwable cause) {
    super(cause);
  }

}
